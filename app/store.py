"""SQLite 持久化：设置、扫描历史、会话密钥。

所有状态都落在一个文件里（默认 /data/app.db），容器重建不丢配置。
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional

DEFAULT_SETTINGS: Dict[str, Any] = {
    # --- Cloudflare ---
    "cf_token": "",
    "zone_name": "",
    "record_name": "",
    "record_type": "A",
    "record_ttl": 300,
    "record_proxied": False,
    "keep_count": 2,
    # --- 探测 ---
    "probe_host": "",
    "probe_path": "/cdn-cgi/trace",
    "probe_port": 443,
    "candidate_count": 200,
    "sample_rounds": 2,
    "concurrency": 48,
    "timeout": 4.0,
    "min_success_rate": 0.5,
    "max_ttfb_ms": 3000,
    "extra_ips": "",
    # --- 调度与更新 ---
    "interval_minutes": 360,
    "auto_update": True,
    "switch_margin_pct": 15,
    # --- 认证（内部）---
    "password_hash": "",
    "session_secret": "",
}

# 不允许通过 API 直接写入的字段
PROTECTED_FIELDS = {"password_hash", "session_secret"}


def hash_password(password: str, salt: Optional[str] = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt.encode("utf-8"),
        n=16384,
        r=8,
        p=1,
        dklen=32,
    )
    return f"scrypt${salt}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    if not stored or not stored.startswith("scrypt$"):
        return False
    try:
        _, salt, _ = stored.split("$", 2)
    except ValueError:
        return False
    return hmac.compare_digest(hash_password(password, salt), stored)


class Store:
    def __init__(self, path: str) -> None:
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.close()
            except Exception:
                pass

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS settings (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    payload TEXT NOT NULL,
                    updated_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    started_at REAL NOT NULL,
                    finished_at REAL NOT NULL,
                    trigger TEXT NOT NULL,
                    tested INTEGER NOT NULL,
                    alive INTEGER NOT NULL,
                    chosen TEXT NOT NULL,
                    applied TEXT NOT NULL,
                    applied_at_all INTEGER NOT NULL DEFAULT 0,
                    detail TEXT NOT NULL,
                    error TEXT NOT NULL DEFAULT ''
                );
                """
            )
            try:
                self._conn.execute(
                    "ALTER TABLE scans ADD COLUMN applied_at_all INTEGER NOT NULL DEFAULT 0"
                )
            except sqlite3.OperationalError:
                pass
            self._conn.commit()

    # ---------------- settings ----------------

    def get_settings(self) -> Dict[str, Any]:
        with self._lock:
            row = self._conn.execute(
                "SELECT payload FROM settings WHERE id = 1"
            ).fetchone()
        data = dict(DEFAULT_SETTINGS)
        if row:
            try:
                data.update(json.loads(row["payload"]))
            except json.JSONDecodeError:
                pass
        if not data.get("session_secret"):
            data["session_secret"] = secrets.token_hex(32)
            self.save_settings(data)
        return data

    def save_settings(self, data: Dict[str, Any]) -> Dict[str, Any]:
        merged = dict(DEFAULT_SETTINGS)
        merged.update({k: v for k, v in data.items() if k not in PROTECTED_FIELDS})
        # 内部字段不走通用合并，避免被默认空值覆盖掉已设置的密码
        current = self.get_settings_raw()
        merged["password_hash"] = data.get("password_hash") or current.get("password_hash", "")
        merged["session_secret"] = (
            data.get("session_secret")
            or current.get("session_secret")
            or secrets.token_hex(32)
        )
        merged["cf_token"] = str(merged.get("cf_token") or "").strip()
        with self._lock:
            self._conn.execute(
                "INSERT INTO settings (id, payload, updated_at) VALUES (1, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET payload = excluded.payload, "
                "updated_at = excluded.updated_at",
                (json.dumps(merged, ensure_ascii=False), time.time()),
            )
            self._conn.commit()
        return merged

    def get_settings_raw(self) -> Dict[str, Any]:
        with self._lock:
            row = self._conn.execute(
                "SELECT payload FROM settings WHERE id = 1"
            ).fetchone()
        if not row:
            return {}
        try:
            return json.loads(row["payload"])
        except json.JSONDecodeError:
            return {}

    def set_password(self, password: str) -> None:
        data = self.get_settings()
        data["password_hash"] = hash_password(password)
        self.save_settings(data)

    # ---------------- scans ----------------

    def add_scan(self, record: Dict[str, Any]) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO scans (started_at, finished_at, trigger, tested, alive,"
                " chosen, applied, applied_at_all, detail, error)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    record["started_at"],
                    record["finished_at"],
                    record["trigger"],
                    record["tested"],
                    record["alive"],
                    json.dumps(record.get("chosen") or [], ensure_ascii=False),
                    json.dumps(record.get("applied") or {}, ensure_ascii=False),
                    1 if record.get("applied_at_all") else 0,
                    json.dumps(record.get("detail") or [], ensure_ascii=False),
                    record.get("error") or "",
                ),
            )
            self._conn.commit()
            scan_id = int(cur.lastrowid or 0)
            # 只保留最近 200 条
            self._conn.execute(
                "DELETE FROM scans WHERE id < (SELECT MAX(id) - 200 FROM scans)"
            )
            self._conn.commit()
        return scan_id

    def recent_scans(self, limit: int = 20) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        out = []
        for row in rows:
            out.append(
                {
                    "id": row["id"],
                    "started_at": row["started_at"],
                    "finished_at": row["finished_at"],
                    "trigger": row["trigger"],
                    "tested": row["tested"],
                    "alive": row["alive"],
                    "chosen": json.loads(row["chosen"] or "[]"),
                    "applied": json.loads(row["applied"] or "{}"),
                    "applied_at_all": bool(row["applied_at_all"]),
                    "detail": json.loads(row["detail"] or "[]"),
                    "error": row["error"],
                }
            )
        return out
