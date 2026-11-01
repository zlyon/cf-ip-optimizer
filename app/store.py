"""SQLite 持久化：全局设置、域名块（target）、扫描历史、会话密钥。

架构：
  - settings 表只放「全局共用」的东西：Cloudflare Token、公共探测参数、调度总开关、密码
  - targets 表放「每个域名块」的独立配置：Zone / 记录 / TTL / 代理 / 保留数量 /
    探测覆盖 / 独立扫描间隔 / 自动更新 / 切换阈值
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
import uuid
from typing import Any, Dict, List, Optional

# 探测路径：默认打业务根路径，让请求真正经过 Worker / 源站。
# 早期版本默认 /cdn-cgi/trace，该端点由 CF 边缘自己应答，探不出
# 「边缘正常但业务路由 403」的 IP（例如 172.65.212.5 对 GitHub 反代全 403）。
DEFAULT_PROBE_PATH = "/"
LEGACY_PROBE_PATH = "/cdn-cgi/trace"
LEGACY_SAMPLE_ROUNDS = 2

DEFAULT_SETTINGS: Dict[str, Any] = {
    # --- Cloudflare（全局共用，多个域名块共享同一个 Token）---
    "cf_token": "",
    # --- 公共探测参数（各域名块默认继承，个别可在块内覆盖）---
    "probe_path": DEFAULT_PROBE_PATH,
    "probe_port": 443,
    "candidate_count": 200,
    "sample_rounds": 3,
    "concurrency": 48,
    "timeout": 4.0,
    "min_success_rate": 0.5,
    "max_ttfb_ms": 3000,
    # --- 调度 ---
    "schedule_enabled": True,
    "interval_minutes": 360,
    "auto_update": True,
    "switch_margin_pct": 15,
    # --- 认证（内部）---
    "password_hash": "",
    "session_secret": "",
}

# 新增域名块时的默认值
DEFAULT_TARGET: Dict[str, Any] = {
    "id": "",
    "label": "",
    "enabled": True,
    "zone_name": "",
    "record_name": "",
    "record_type": "A",
    "record_ttl": 300,
    "record_proxied": False,
    "keep_count": 2,
    # 留空表示继承全局
    "probe_host": "",
    "probe_path": "",
    "extra_ips": "",
    # 每个域独立调度
    "interval_minutes": 360,
    "auto_update": True,
    "switch_margin_pct": 15,
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


def new_target_id() -> str:
    return uuid.uuid4().hex[:12]


def _describe_dir(path: str) -> str:
    """给出目录/文件的属主与权限，用于把 sqlite 的干瘪报错变成可操作提示。"""
    try:
        st = os.stat(path)
    except OSError:
        return f"{path}（不存在）"
    import stat as _stat

    mode = _stat.filemode(st.st_mode)
    owner = f"uid={st.st_uid} gid={st.st_gid}"
    try:
        import grp
        import pwd

        owner += f"（{pwd.getpwuid(st.st_uid).pw_name}:{grp.getgrgid(st.st_gid).gr_name}）"
    except Exception:
        pass
    return f"{path}（{mode} {owner}）"


def _connect_sqlite(path: str) -> "sqlite3.Connection":
    """打开数据库，失败时抛出带排查线索的 RuntimeError。

    容器里最典型的事故是 bind mount 的目录由 root 创建（默认 0755），
    而进程跑在非 root 用户下，导致 sqlite 只报 unable to open database file，
    看不出是权限问题。这里提前判定并说清楚。
    """
    directory = os.path.dirname(path) or "."
    try:
        os.makedirs(directory, exist_ok=True)
    except PermissionError as exc:
        raise RuntimeError(
            f"数据目录无法创建：{_describe_dir(directory)}\n"
            f"当前进程 uid={os.geteuid() if hasattr(os, 'geteuid') else '?'}，"
            f"请确认挂载目录对该用户可写，或在 compose 里设置 PUID/PGID。"
        ) from exc
    except OSError as exc:
        raise RuntimeError(
            f"数据目录不可用：{directory}\n"
            f"原始错误：{exc}\n"
            f"请确认挂载点存在且路径的每一级都是目录，而不是某个文件。"
        ) from exc

    if not os.access(directory, os.W_OK):
        raise RuntimeError(
            f"数据目录不可写：{_describe_dir(directory)}\n"
            f"当前进程 uid={os.geteuid() if hasattr(os, 'geteuid') else '?'}。\n"
            f"宿主机上执行一次即可修复：sudo chown -R 1000:1000 <你挂载的 data 目录>\n"
            f"（或用 PUID/PGID 指定成该目录的属主）"
        )

    try:
        return sqlite3.connect(path, check_same_thread=False)
    except sqlite3.OperationalError as exc:
        raise RuntimeError(
            f"无法打开数据库：{_describe_dir(path)}\n"
            f"目录：{_describe_dir(directory)}\n"
            f"原始错误：{exc}\n"
            f"常见原因：挂载目录属主不是容器运行用户，或该路径被挂成了只读。"
        ) from exc


class Store:
    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.RLock()
        self._conn = _connect_sqlite(path)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()
        self._migrate_legacy_target()
        self._migrate_probe_path()

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
                CREATE TABLE IF NOT EXISTS targets (
                    id TEXT PRIMARY KEY,
                    position INTEGER NOT NULL DEFAULT 0,
                    payload TEXT NOT NULL,
                    created_at REAL NOT NULL,
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
            for ddl in (
                "ALTER TABLE scans ADD COLUMN applied_at_all INTEGER NOT NULL DEFAULT 0",
                "ALTER TABLE scans ADD COLUMN target_id TEXT NOT NULL DEFAULT ''",
                "ALTER TABLE scans ADD COLUMN target_label TEXT NOT NULL DEFAULT ''",
            ):
                try:
                    self._conn.execute(ddl)
                except sqlite3.OperationalError:
                    pass
            self._conn.commit()

    def _migrate_legacy_target(self) -> None:
        """老版本是单域扁平配置，首次升级时自动转成一个域名块。"""
        if self.list_targets():
            return
        raw = self.get_settings_raw()
        if not raw.get("record_name"):
            return
        target = dict(DEFAULT_TARGET)
        for key in (
            "zone_name",
            "record_name",
            "record_type",
            "record_ttl",
            "record_proxied",
            "keep_count",
            "probe_host",
            "extra_ips",
            "interval_minutes",
            "auto_update",
            "switch_margin_pct",
        ):
            if key in raw and raw[key] not in (None, ""):
                target[key] = raw[key]
        target["label"] = str(raw.get("record_name") or "迁移的域名")
        self.upsert_target(target)

    def _migrate_probe_path(self) -> None:
        """把两个「旧默认值」换成新的。

        1. 探测路径 /cdn-cgi/trace → /：该端点由 CF 边缘自己应答，不经过
           Worker/源站，用它当探针会漏掉「边缘正常、业务路由 403」的 IP。
        2. 采样轮数 2 → 3：2 轮时一次抖动就是 50%，刚好卡在 0.5 阈值上，
           时好时坏的 IP 常常蒙混过关。
        只在用户没动过默认值时才迁移。
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT payload FROM settings WHERE id = 1"
            ).fetchone()
            if not row:
                return
            try:
                payload = json.loads(row["payload"])
            except json.JSONDecodeError:
                return
            touched = False
            if payload.get("probe_path") == LEGACY_PROBE_PATH:
                payload["probe_path"] = DEFAULT_PROBE_PATH
                touched = True
            if payload.get("sample_rounds") == LEGACY_SAMPLE_ROUNDS:
                payload["sample_rounds"] = DEFAULT_SETTINGS["sample_rounds"]
                touched = True
            if not touched:
                return
            self._conn.execute(
                "UPDATE settings SET payload = ?, updated_at = ? WHERE id = 1",
                (json.dumps(payload, ensure_ascii=False), time.time()),
            )
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

    # ---------------- targets ----------------

    def list_targets(self) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, payload FROM targets ORDER BY position ASC, created_at ASC"
            ).fetchall()
        out: List[Dict[str, Any]] = []
        for row in rows:
            try:
                payload = json.loads(row["payload"])
            except json.JSONDecodeError:
                continue
            item = dict(DEFAULT_TARGET)
            item.update(payload)
            item["id"] = row["id"]
            out.append(item)
        return out

    def get_target(self, target_id: str) -> Optional[Dict[str, Any]]:
        for item in self.list_targets():
            if item["id"] == target_id:
                return item
        return None

    def find_target_by_record(
        self, zone_name: str, record_name: str, record_type: str, exclude_id: str = ""
    ) -> Optional[Dict[str, Any]]:
        for item in self.list_targets():
            if item["id"] == exclude_id:
                continue
            if (
                str(item.get("zone_name", "")).lower() == zone_name.lower()
                and str(item.get("record_name", "")).lower() == record_name.lower()
                and str(item.get("record_type", "")).upper() == record_type.upper()
            ):
                return item
        return None

    def upsert_target(self, data: Dict[str, Any]) -> Dict[str, Any]:
        now = time.time()
        target_id = str(data.get("id") or "").strip() or new_target_id()
        with self._lock:
            row = self._conn.execute(
                "SELECT position, created_at, payload FROM targets WHERE id = ?",
                (target_id,),
            ).fetchone()
            # 合并语义：先取默认值，再叠已有配置，最后叠本次改动，
            # 这样局部更新（比如只改 interval）不会把记录名冲掉。
            merged = dict(DEFAULT_TARGET)
            if row:
                try:
                    merged.update(json.loads(row["payload"]))
                except json.JSONDecodeError:
                    pass
            merged.update({k: v for k, v in data.items() if k != "id"})
            merged["id"] = target_id

            if row:
                position = int(row["position"])
                created_at = float(row["created_at"])
            else:
                position_row = self._conn.execute(
                    "SELECT COALESCE(MAX(position), 0) + 1 AS pos FROM targets"
                ).fetchone()
                position = int(position_row["pos"] or 1)
                created_at = now
            self._conn.execute(
                "INSERT INTO targets (id, position, payload, created_at, updated_at)"
                " VALUES (?,?,?,?,?)"
                " ON CONFLICT(id) DO UPDATE SET payload = excluded.payload,"
                " updated_at = excluded.updated_at",
                (
                    target_id,
                    position,
                    json.dumps(merged, ensure_ascii=False),
                    created_at,
                    now,
                ),
            )
            self._conn.commit()
        return merged

    def delete_target(self, target_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute("DELETE FROM targets WHERE id = ?", (target_id,))
            self._conn.commit()
            return (cur.rowcount or 0) > 0

    def count_targets(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS n FROM targets").fetchone()
        return int(row["n"] or 0)

    # ---------------- scans ----------------

    def add_scan(self, record: Dict[str, Any]) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO scans (started_at, finished_at, trigger, tested, alive,"
                " chosen, applied, applied_at_all, detail, error, target_id, target_label)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
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
                    record.get("target_id") or "",
                    record.get("target_label") or "",
                ),
            )
            self._conn.commit()
            scan_id = int(cur.lastrowid or 0)
            # 只保留最近 300 条
            self._conn.execute(
                "DELETE FROM scans WHERE id < (SELECT MAX(id) - 300 FROM scans)"
            )
            self._conn.commit()
        return scan_id

    def recent_scans(self, limit: int = 20, target_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            if target_id:
                rows = self._conn.execute(
                    "SELECT * FROM scans WHERE target_id = ? ORDER BY id DESC LIMIT ?",
                    (target_id, limit),
                ).fetchall()
            else:
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
                    "target_id": row["target_id"],
                    "target_label": row["target_label"],
                }
            )
        return out
