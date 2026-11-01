"""核心逻辑自测：候选采样、colo 解析、DNS 记录同步、设置持久化。

运行：python -m unittest discover -s tests -t .
"""
from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

# 导入 app.main 会在模块级创建 Store，先把数据目录指到临时位置，
# 避免测试在 /data 或当前盘符根目录留下文件。
_TMP_DIR = tempfile.mkdtemp(prefix="cfip-test-")
os.environ.setdefault("DATA_DIR", _TMP_DIR)
os.environ.setdefault("DB_PATH", os.path.join(_TMP_DIR, "app.db"))

from app.cloudflare import CloudflareClient  # noqa: E402
from app.scanner import _parse_colo, sample_candidates  # noqa: E402
from app.store import Store, hash_password, verify_password  # noqa: E402


class CandidateSamplingTest(unittest.TestCase):
    def test_returns_requested_count_and_is_unique(self):
        ips = sample_candidates(300, 4)
        self.assertEqual(len(ips), 300)
        self.assertEqual(len(set(ips)), 300)

    def test_extra_ips_come_first(self):
        ips = sample_candidates(10, 4, extra=["104.16.0.1", "104.17.128.1"])
        self.assertEqual(ips[:2], ["104.16.0.1", "104.17.128.1"])
        self.assertEqual(len(ips), 10)

    def test_extra_cidr_is_expanded(self):
        ips = sample_candidates(8, 4, extra=["104.26.0.0/24"])
        self.assertEqual(len(ips), 8)
        for ip in ips[:8]:
            self.assertTrue(ip.startswith("104.26.0."))

    def test_ipv6_candidates(self):
        ips = sample_candidates(20, 6)
        self.assertEqual(len(ips), 20)
        self.assertTrue(all(":" in ip for ip in ips))


class ColoParsingTest(unittest.TestCase):
    def test_from_cf_ray_header(self):
        self.assertEqual(_parse_colo({"cf-ray": "8f2a1b2c3d4e5f60-HKG"}, b""), "HKG")

    def test_from_trace_body(self):
        body = b"fl=1f2\nh=cloudflare.com\nip=1.2.3.4\ncolo=NRT\n"
        self.assertEqual(_parse_colo({}, body), "NRT")

    def test_unknown(self):
        self.assertEqual(_parse_colo({}, b""), "")


class SyncRecordsTest(unittest.TestCase):
    def _client(self, existing):
        client = CloudflareClient("token-1234567890")
        client.find_zone_id = lambda name: "zone-1"  # type: ignore[assignment]
        client.list_records = lambda z, n, t: list(existing)  # type: ignore[assignment]
        self.calls = []
        client.create_record = lambda *a, **kw: self.calls.append(("create", a[3]))  # type: ignore[assignment]
        client.delete_record = lambda z, rid: self.calls.append(("delete", rid))  # type: ignore[assignment]
        client.update_record = lambda z, rid, **kw: self.calls.append(("update", kw["content"]))  # type: ignore[assignment]
        return client

    def test_replaces_stale_ips_only(self):
        existing = [
            {"id": "r1", "content": "1.1.1.1", "ttl": 300, "proxied": False},
            {"id": "r2", "content": "2.2.2.2", "ttl": 300, "proxied": False},
        ]
        client = self._client(existing)
        summary = client.sync_records(
            zone_name="example.com",
            name="cdn.example.com",
            record_type="A",
            ips=["2.2.2.2", "3.3.3.3"],
            ttl=300,
            proxied=False,
        )
        self.assertEqual(summary["created"], ["3.3.3.3"])
        self.assertEqual(summary["deleted"], ["1.1.1.1"])
        self.assertEqual(summary["kept"], ["2.2.2.2"])
        self.assertIn(("create", "3.3.3.3"), self.calls)
        self.assertIn(("delete", "r1"), self.calls)
        self.assertNotIn(("delete", "r2"), self.calls)

    def test_empty_target_refuses_to_run(self):
        client = self._client([])
        with self.assertRaises(Exception):
            client.sync_records(
                zone_name="example.com",
                name="cdn.example.com",
                record_type="A",
                ips=[],
            )


class SettingsStoreTest(unittest.TestCase):
    def _fresh_store(self):
        tmp = tempfile.mkdtemp(prefix="cfip-store-")
        store = Store(os.path.join(tmp, "app.db"))

        def cleanup():
            store.close()
            shutil.rmtree(tmp, ignore_errors=True)

        self.addCleanup(cleanup)
        return store

    def test_password_survives_settings_write(self):
        store = self._fresh_store()
        store.set_password("secret123")
        data = store.get_settings()
        data["zone_name"] = "example.com"
        store.save_settings(data)
        again = store.get_settings()
        self.assertTrue(verify_password("secret123", again["password_hash"]))
        self.assertEqual(again["zone_name"], "example.com")
        self.assertEqual(again["session_secret"], data["session_secret"])

    def test_token_not_overwritten_by_mask(self):
        store = self._fresh_store()
        data = store.get_settings()
        data["cf_token"] = "real-token-value"
        store.save_settings(data)

        from app.main import public_settings, sanitize

        current = store.get_settings()
        masked = public_settings(current)
        self.assertIn("*", masked["cf_token"])
        merged = sanitize({"cf_token": masked["cf_token"]}, current)
        self.assertEqual(merged["cf_token"], "real-token-value")

    def test_hash_is_salted(self):
        a = hash_password("same-password")
        b = hash_password("same-password")
        self.assertNotEqual(a, b)
        self.assertTrue(verify_password("same-password", a))
        self.assertFalse(verify_password("other-password", a))


if __name__ == "__main__":
    unittest.main()
