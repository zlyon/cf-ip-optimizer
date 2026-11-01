"""核心逻辑自测：候选采样、colo 解析、DNS 记录同步、设置持久化。

运行：python -m unittest discover -s tests -t .
"""
from __future__ import annotations

import os
import shutil
import tempfile
import time
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
    def _client(self, existing, cname=None):
        client = CloudflareClient("token-1234567890")
        client.find_zone_id = lambda name: "zone-1"  # type: ignore[assignment]
        client.find_conflicting_cname = lambda z, n, t: cname  # type: ignore[assignment]
        client.list_records = lambda z, n, t: list(existing)  # type: ignore[assignment]
        self.calls = []
        client.create_record = lambda *a, **kw: self.calls.append(("create", a[3]))  # type: ignore[assignment]
        client.delete_record = lambda z, rid: self.calls.append(("delete", rid))  # type: ignore[assignment]
        client.update_record = lambda z, rid, **kw: self.calls.append(("update", kw["content"]))  # type: ignore[assignment]
        return client

    def test_cname_conflict_gives_actionable_error(self):
        client = self._client([], cname={"id": "c1", "type": "CNAME", "content": "cdn.example.net"})
        with self.assertRaises(Exception) as ctx:
            client.sync_records(
                zone_name="example.com",
                name="cdn.example.com",
                record_type="A",
                ips=["1.1.1.1"],
            )
        message = str(ctx.exception)
        self.assertIn("CNAME", message)
        self.assertIn("cdn.example.net", message)
        self.assertEqual(self.calls, [])

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


class MultiTargetStoreTest(unittest.TestCase):
    def _fresh_store(self):
        tmp = tempfile.mkdtemp(prefix="cfip-target-")
        store = Store(os.path.join(tmp, "app.db"))

        def cleanup():
            store.close()
            shutil.rmtree(tmp, ignore_errors=True)

        self.addCleanup(cleanup)
        return store

    def test_create_list_update_delete(self):
        store = self._fresh_store()
        created = store.upsert_target({"label": "主站", "zone_name": "a.com", "record_name": "cdn.a.com"})
        self.assertTrue(created["id"])

        again = store.upsert_target({"label": "备站", "zone_name": "b.com", "record_name": "cdn.b.com"})
        self.assertNotEqual(created["id"], again["id"])
        self.assertEqual(store.count_targets(), 2)

        loaded = store.get_target(created["id"])
        self.assertEqual(loaded["record_name"], "cdn.a.com")
        # 未提供的字段用默认值补全
        self.assertEqual(loaded["record_type"], "A")
        self.assertEqual(loaded["keep_count"], 2)

        store.upsert_target({"id": created["id"], "label": "主站改", "interval_minutes": 30})
        updated = store.get_target(created["id"])
        self.assertEqual(updated["label"], "主站改")
        self.assertEqual(updated["interval_minutes"], 30)
        self.assertEqual(updated["record_name"], "cdn.a.com")
        self.assertEqual(store.count_targets(), 2)

        self.assertTrue(store.delete_target(created["id"]))
        self.assertFalse(store.delete_target(created["id"]))
        self.assertEqual(store.count_targets(), 1)

    def test_order_is_stable_by_insertion(self):
        store = self._fresh_store()
        ids = [store.upsert_target({"record_name": f"n{i}.example.com"})["id"] for i in range(3)]
        listed = [t["id"] for t in store.list_targets()]
        self.assertEqual(listed, ids)

    def test_duplicate_record_lookup(self):
        store = self._fresh_store()
        a = store.upsert_target({"zone_name": "a.com", "record_name": "cdn.a.com", "record_type": "A"})
        store.upsert_target({"zone_name": "a.com", "record_name": "cdn.a.com", "record_type": "AAAA"})
        hit = store.find_target_by_record("a.com", "cdn.a.com", "A")
        self.assertIsNotNone(hit)
        self.assertEqual(hit["id"], a["id"])
        # 同记录不同类型不算冲突
        self.assertIsNone(store.find_target_by_record("a.com", "cdn.a.com", "A", exclude_id=a["id"]))
        self.assertIsNotNone(store.find_target_by_record("a.com", "cdn.a.com", "AAAA"))

    def test_legacy_flat_settings_migrate_to_one_target(self):
        store = self._fresh_store()
        data = store.get_settings()
        data.update(
            {
                "zone_name": "old.com",
                "record_name": "tg.old.com",
                "keep_count": 3,
                "interval_minutes": 120,
                "record_ttl": 120,
            }
        )
        store.save_settings(data)

        # 重新打开，触发迁移
        store2 = Store(os.path.join(os.path.dirname(store.path), "app.db"))
        self.addCleanup(store2.close)
        targets = store2.list_targets()
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0]["record_name"], "tg.old.com")
        self.assertEqual(targets[0]["keep_count"], 3)
        self.assertEqual(targets[0]["interval_minutes"], 120)
        self.assertEqual(targets[0]["record_ttl"], 120)

    def test_scan_history_keeps_target_info(self):
        store = self._fresh_store()
        store.add_scan(
            {
                "started_at": 1.0,
                "finished_at": 2.0,
                "trigger": "manual",
                "tested": 10,
                "alive": 3,
                "chosen": ["1.1.1.1"],
                "applied": {"applied": True},
                "detail": [],
                "target_id": "t1",
                "target_label": "主站",
            }
        )
        rows = store.recent_scans(5, target_id="t1")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["target_label"], "主站")
        self.assertEqual(store.recent_scans(5, target_id="t2"), [])


class TargetSanitizeTest(unittest.TestCase):
    def test_normalizes_and_clamps(self):
        from app.main import sanitize_target

        data = sanitize_target(
            {
                "label": "  主站  ",
                "zone_name": " Example.COM. ",
                "record_name": " CDN.Example.com ",
                "record_type": "aaaa",
                "record_ttl": 99999,
                "keep_count": 99,
                "interval_minutes": -5,
                "switch_margin_pct": 200,
                "probe_path": "cdn-cgi/trace",
            }
        )
        self.assertEqual(data["label"], "主站")
        self.assertEqual(data["zone_name"], "example.com")
        self.assertEqual(data["record_name"], "cdn.example.com")
        self.assertEqual(data["record_type"], "AAAA")
        self.assertEqual(data["record_ttl"], 86400)
        self.assertEqual(data["keep_count"], 10)
        self.assertEqual(data["interval_minutes"], 0)
        self.assertEqual(data["switch_margin_pct"], 100)
        self.assertEqual(data["probe_path"], "/cdn-cgi/trace")

    def test_invalid_type_falls_back_to_a(self):
        from app.main import sanitize_target

        self.assertEqual(sanitize_target({"record_type": "TXT"})["record_type"], "A")

    def test_partial_update_keeps_other_fields(self):
        from app.main import sanitize_target

        current = {
            "id": "abc",
            "label": "主站",
            "zone_name": "a.com",
            "record_name": "cdn.a.com",
            "extra_ips": "1.1.1.1",
            "interval_minutes": 60,
        }
        data = sanitize_target({"label": "改名"}, current)
        self.assertEqual(data["label"], "改名")
        self.assertEqual(data["record_name"], "cdn.a.com")
        self.assertEqual(data["extra_ips"], "1.1.1.1")
        self.assertEqual(data["interval_minutes"], 60)


class SchedulerTest(unittest.TestCase):
    def _optimizer(self, store):
        from app.runner import Optimizer

        return Optimizer(store)

    def _store_with(self, targets, settings=None):
        tmp = tempfile.mkdtemp(prefix="cfip-sched-")
        store = Store(os.path.join(tmp, "app.db"))

        def cleanup():
            store.close()
            shutil.rmtree(tmp, ignore_errors=True)

        self.addCleanup(cleanup)
        if settings:
            data = store.get_settings()
            data.update(settings)
            store.save_settings(data)
        for target in targets:
            store.upsert_target(target)
        return store

    def test_only_enabled_targets_get_a_slot(self):
        store = self._store_with(
            [
                {"label": "开", "record_name": "a.com", "interval_minutes": 60},
                {"label": "停", "record_name": "b.com", "interval_minutes": 60, "enabled": False},
                {"label": "不定时", "record_name": "c.com", "interval_minutes": 0},
            ]
        )
        opt = self._optimizer(store)
        opt._sync_schedule(initial=True)
        states = {t["label"]: opt.state_for(t["id"]) for t in store.list_targets()}
        self.assertGreater(states["开"].next_run_at, 0)
        self.assertEqual(states["停"].next_run_at, 0)
        self.assertEqual(states["不定时"].next_run_at, 0)

    def test_master_switch_clears_all_slots(self):
        store = self._store_with(
            [{"record_name": "a.com", "interval_minutes": 60}],
            settings={"schedule_enabled": False},
        )
        opt = self._optimizer(store)
        opt._sync_schedule(initial=True)
        target = store.list_targets()[0]
        self.assertEqual(opt.state_for(target["id"]).next_run_at, 0)

    def test_reschedule_after_run_uses_interval(self):
        store = self._store_with([{"record_name": "a.com", "interval_minutes": 30}])
        opt = self._optimizer(store)
        target = store.list_targets()[0]
        opt._reschedule_after_run(target)
        state = opt.state_for(target["id"])
        self.assertGreater(state.next_run_at, time.time() + 29 * 60)

    def test_snapshot_drops_deleted_target_state(self):
        store = self._store_with([{"record_name": "a.com"}])
        opt = self._optimizer(store)
        target = store.list_targets()[0]
        opt.state_for(target["id"]).last_error = "旧错误"
        store.delete_target(target["id"])
        opt._sync_schedule(initial=False)
        self.assertEqual(opt.states, {})


class StoreStartupErrorTest(unittest.TestCase):
    """容器里最常见的事故：挂载目录不可写，sqlite 只回一句
    "unable to open database file"，看不出是权限问题。"""

    def test_creates_missing_nested_data_dir(self):
        base = tempfile.mkdtemp(prefix="cfip-nested-")
        self.addCleanup(shutil.rmtree, base, True)
        deep = os.path.join(base, "a", "b", "c", "app.db")
        store = Store(deep)
        self.addCleanup(store.close)
        self.assertTrue(os.path.isfile(deep))

    def test_error_names_the_path_and_is_actionable(self):
        base = tempfile.mkdtemp(prefix="cfip-blocked-")
        self.addCleanup(shutil.rmtree, base, True)
        blocker = os.path.join(base, "iamafile")
        with open(blocker, "w", encoding="utf-8") as fh:
            fh.write("x")
        bad = os.path.join(blocker, "sub", "app.db")
        with self.assertRaises(RuntimeError) as ctx:
            Store(bad)
        msg = str(ctx.exception)
        self.assertIn("数据目录", msg)
        # 必须带上路径，否则用户不知道该去改哪个目录
        self.assertIn("iamafile", msg)


class EntrypointSmokeTest(unittest.TestCase):
    """入口脚本要能原样把命令 exec 出去（容器里靠它降权后启动 uvicorn）。"""

    def test_execs_the_given_command(self):
        import subprocess
        import sys

        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        probe = os.path.join(_TMP_DIR, "ep_probe.py")
        with open(probe, "w", encoding="utf-8") as fh:
            fh.write("print('ENTRYPOINT_RAN')\n")
        env = dict(os.environ, DATA_DIR=_TMP_DIR)
        result = subprocess.run(
            [sys.executable, os.path.join(root, "docker-entrypoint.py"), sys.executable, probe],
            capture_output=True,
            text=True,
            env=env,
            timeout=60,
        )
        self.assertIn("ENTRYPOINT_RAN", result.stdout)
        self.assertEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
