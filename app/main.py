"""FastAPI 应用：Web 管理界面 + REST API。

配置分两层：
  - 全局：Cloudflare Token、公共探测参数、调度总开关（PUT /api/settings）
  - 域名块：每个域/记录一套独立配置（POST/PUT/DELETE /api/targets/{id}）
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .cloudflare import CloudflareClient, CloudflareError
from .runner import Optimizer
from .store import DEFAULT_TARGET, Store, verify_password

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = os.getenv("DATA_DIR", "/data")
DB_PATH = os.getenv("DB_PATH", os.path.join(DATA_DIR, "app.db"))
SESSION_COOKIE = "cfip_session"
SESSION_TTL = 7 * 24 * 3600

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)-7s %(message)s",
    datefmt="%H:%M:%S",
)
LOGGER = logging.getLogger("cfip")

store = Store(DB_PATH)
optimizer = Optimizer(store)
_login_failures: Dict[str, list] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    await optimizer.start()
    LOGGER.info("服务已启动，数据目录 %s", DATA_DIR)
    yield
    await optimizer.stop()


app = FastAPI(title="Cloudflare 优选 IP 自动更新", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


# ---------------- 会话 ----------------

def _sign(secret: str, payload: str) -> str:
    return hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()


def _issue_cookie(secret: str) -> str:
    expires = str(int(time.time()) + SESSION_TTL)
    return f"{expires}.{_sign(secret, expires)}"


def _cookie_valid(secret: str, value: Optional[str]) -> bool:
    if not value or "." not in value:
        return False
    expires, signature = value.rsplit(".", 1)
    if not expires.isdigit() or int(expires) < time.time():
        return False
    return hmac.compare_digest(_sign(secret, expires), signature)


def require_auth(request: Request) -> None:
    settings = store.get_settings()
    if not settings.get("password_hash"):
        raise HTTPException(status_code=401, detail="尚未初始化密码")
    if not _cookie_valid(settings["session_secret"], request.cookies.get(SESSION_COOKIE)):
        raise HTTPException(status_code=401, detail="未登录")


def _client_key(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# ---------------- 工具 ----------------

def mask_token(token: str) -> str:
    token = token or ""
    if not token:
        return ""
    if len(token) <= 10:
        return "*" * len(token)
    return f"{token[:6]}{'*' * 8}{token[-4:]}"


def _masked(value: str) -> bool:
    return "*" in (value or "")


def public_settings(settings: Dict[str, Any]) -> Dict[str, Any]:
    out = {
        k: v
        for k, v in settings.items()
        if k not in ("password_hash", "session_secret")
    }
    out["cf_token"] = mask_token(settings.get("cf_token", ""))
    out["has_token"] = bool(settings.get("cf_token"))
    out["password_set"] = bool(settings.get("password_hash"))
    return out


def public_target(target: Dict[str, Any]) -> Dict[str, Any]:
    out = {k: v for k, v in target.items() if k != "payload"}
    out["configured"] = bool(
        str(target.get("zone_name") or "").strip()
        and str(target.get("record_name") or "").strip()
    )
    return out


def _clamp(value: Any, default: Any, minimum: Any, maximum: Any) -> Any:
    try:
        number = type(default)(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, number))


def sanitize(incoming: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, Any]:
    """全局设置。"""
    data = dict(current)

    token = str(incoming.get("cf_token", "")).strip()
    if token and not _masked(token):
        data["cf_token"] = token

    path = str(incoming.get("probe_path", current.get("probe_path", "/cdn-cgi/trace"))).strip()
    data["probe_path"] = path if path.startswith("/") else "/" + path
    data["probe_port"] = _clamp(incoming.get("probe_port"), 443, 1, 65535)
    data["candidate_count"] = _clamp(incoming.get("candidate_count"), 200, 10, 5000)
    data["sample_rounds"] = _clamp(incoming.get("sample_rounds"), 2, 1, 6)
    data["concurrency"] = _clamp(incoming.get("concurrency"), 48, 1, 256)
    data["timeout"] = _clamp(incoming.get("timeout"), 4.0, 1.0, 30.0)
    data["min_success_rate"] = _clamp(incoming.get("min_success_rate"), 0.5, 0.0, 1.0)
    data["max_ttfb_ms"] = _clamp(incoming.get("max_ttfb_ms"), 3000, 0, 60000)

    data["schedule_enabled"] = bool(
        incoming.get("schedule_enabled", current.get("schedule_enabled", True))
    )
    data["interval_minutes"] = _clamp(incoming.get("interval_minutes"), 360, 0, 10080)
    data["auto_update"] = bool(incoming.get("auto_update", current.get("auto_update", True)))
    data["switch_margin_pct"] = _clamp(incoming.get("switch_margin_pct"), 15, 0, 100)
    return data


def sanitize_target(incoming: Dict[str, Any], current: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """单个域名块。current 为空表示新建，缺省值取 DEFAULT_TARGET。"""
    base = dict(DEFAULT_TARGET)
    if current:
        base.update(current)

    def pick(key: str, default: Any = "") -> Any:
        value = incoming.get(key, base.get(key, default))
        return default if value is None else value

    data: Dict[str, Any] = dict(base)
    data["label"] = str(pick("label", ""))[:40].strip()
    zone = str(pick("zone_name", "")).strip().lower().rstrip(".")
    data["zone_name"] = zone
    data["record_name"] = str(pick("record_name", "")).strip().lower().rstrip(".")
    record_type = str(pick("record_type", "A")).upper()
    data["record_type"] = record_type if record_type in ("A", "AAAA") else "A"
    data["record_ttl"] = _clamp(pick("record_ttl", 300), 300, 1, 86400)
    data["record_proxied"] = bool(pick("record_proxied", False))
    data["keep_count"] = _clamp(pick("keep_count", 2), 2, 1, 10)
    data["probe_host"] = str(pick("probe_host", "")).strip()
    path = str(pick("probe_path", "")).strip()
    data["probe_path"] = ("/" + path) if path and not path.startswith("/") else path
    data["extra_ips"] = str(pick("extra_ips", ""))
    data["interval_minutes"] = _clamp(pick("interval_minutes", 360), 360, 0, 10080)
    data["auto_update"] = bool(pick("auto_update", True))
    data["switch_margin_pct"] = _clamp(pick("switch_margin_pct", 15), 15, 0, 100)
    data["enabled"] = bool(pick("enabled", True))
    return data


# ---------------- 页面 ----------------

@app.get("/")
async def index() -> Any:
    return FileResponse(str(BASE_DIR / "static" / "index.html"))


@app.get("/healthz")
async def healthz() -> Dict[str, Any]:
    return {"ok": True, "time": time.time()}


# ---------------- 认证接口 ----------------

@app.post("/api/setup")
async def setup(payload: Dict[str, Any], response: Response) -> Dict[str, Any]:
    settings = store.get_settings()
    if settings.get("password_hash"):
        raise HTTPException(status_code=400, detail="已初始化，请直接登录")
    password = str(payload.get("password") or "")
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="密码至少 8 位")
    store.set_password(password)
    secret = store.get_settings()["session_secret"]
    response.set_cookie(SESSION_COOKIE, _issue_cookie(secret), httponly=True, samesite="lax", max_age=SESSION_TTL)
    LOGGER.info("管理密码已初始化")
    return {"ok": True}


@app.post("/api/login")
async def login(payload: Dict[str, Any], request: Request, response: Response) -> Dict[str, Any]:
    key = _client_key(request)
    now = time.time()
    attempts = [t for t in _login_failures.get(key, []) if now - t < 300]
    if len(attempts) >= 8:
        raise HTTPException(status_code=429, detail="尝试过于频繁，请 5 分钟后再试")

    settings = store.get_settings()
    password = str(payload.get("password") or "")
    if not verify_password(password, settings.get("password_hash", "")):
        attempts.append(now)
        _login_failures[key] = attempts
        raise HTTPException(status_code=401, detail="密码错误")

    _login_failures.pop(key, None)
    response.set_cookie(
        SESSION_COOKIE,
        _issue_cookie(settings["session_secret"]),
        httponly=True,
        samesite="lax",
        max_age=SESSION_TTL,
    )
    return {"ok": True}


@app.post("/api/logout")
async def logout(response: Response) -> Dict[str, Any]:
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ok": True}


@app.post("/api/password")
async def change_password(payload: Dict[str, Any], _: None = Depends(require_auth)) -> Dict[str, Any]:
    password = str(payload.get("password") or "")
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="密码至少 8 位")
    store.set_password(password)
    LOGGER.info("管理密码已更新")
    return {"ok": True}


# ---------------- 业务接口 ----------------

@app.get("/api/state")
async def get_state(request: Request) -> Dict[str, Any]:
    """未登录时只回初始化/登录状态，不泄露任何配置。"""
    settings = store.get_settings()
    initialized = bool(settings.get("password_hash"))
    authed = initialized and _cookie_valid(
        settings.get("session_secret", ""), request.cookies.get(SESSION_COOKIE)
    )
    payload: Dict[str, Any] = {
        "initialized": initialized,
        "authenticated": authed,
        "version": _version(),
    }
    if authed:
        payload["settings"] = public_settings(settings)
    return payload


@app.get("/api/dashboard")
async def dashboard(request: Request, _: None = Depends(require_auth)) -> Dict[str, Any]:
    settings = store.get_settings()
    snapshot = optimizer.snapshot()
    states = snapshot.get("targets", {})
    targets: List[Dict[str, Any]] = []
    for target in store.list_targets():
        item = public_target(target)
        item["state"] = states.get(target["id"], {})
        targets.append(item)
    return {
        "settings": public_settings(settings),
        "targets": targets,
        "state": snapshot,
        "history": store.recent_scans(20),
        "logs": optimizer.log_handler.snapshot(150),
        "version": _version(),
    }


@app.put("/api/settings")
async def update_settings(payload: Dict[str, Any], _: None = Depends(require_auth)) -> Dict[str, Any]:
    current = store.get_settings()
    merged = sanitize(payload, current)
    saved = store.save_settings(merged)
    optimizer.reload_schedule()
    LOGGER.info("全局设置已保存")
    return {"ok": True, "settings": public_settings(saved)}


@app.post("/api/targets")
async def create_target(payload: Optional[Dict[str, Any]] = None, _: None = Depends(require_auth)) -> Dict[str, Any]:
    settings = store.get_settings()
    incoming = dict(payload or {})
    # 新建块继承全局调度默认值
    incoming.setdefault("interval_minutes", settings.get("interval_minutes", 360))
    incoming.setdefault("auto_update", settings.get("auto_update", True))
    incoming.setdefault("switch_margin_pct", settings.get("switch_margin_pct", 15))
    data = sanitize_target(incoming)
    if data["zone_name"] and data["record_name"]:
        clash = store.find_target_by_record(
            data["zone_name"], data["record_name"], data["record_type"]
        )
        if clash:
            raise HTTPException(status_code=400, detail="已存在同名记录的域名块")
    saved = store.upsert_target(data)
    optimizer.reload_schedule()
    LOGGER.info("新增域名块：%s", saved.get("record_name") or saved["id"])
    return {"ok": True, "target": public_target(saved)}


@app.put("/api/targets/{target_id}")
async def update_target(
    target_id: str, payload: Dict[str, Any], _: None = Depends(require_auth)
) -> Dict[str, Any]:
    current = store.get_target(target_id)
    if not current:
        raise HTTPException(status_code=404, detail="域名块不存在")
    data = sanitize_target(payload, current)
    data["id"] = target_id
    if data["zone_name"] and data["record_name"]:
        clash = store.find_target_by_record(
            data["zone_name"], data["record_name"], data["record_type"], exclude_id=target_id
        )
        if clash:
            raise HTTPException(status_code=400, detail="另一个域名块已使用同名记录")
    saved = store.upsert_target(data)
    optimizer.reload_schedule()
    LOGGER.info("域名块已更新：%s", saved.get("record_name") or target_id)
    return {"ok": True, "target": public_target(saved)}


@app.delete("/api/targets/{target_id}")
async def delete_target(target_id: str, _: None = Depends(require_auth)) -> Dict[str, Any]:
    target = store.get_target(target_id)
    if not target:
        raise HTTPException(status_code=404, detail="域名块不存在")
    store.delete_target(target_id)
    optimizer.states.pop(target_id, None)
    optimizer.reload_schedule()
    LOGGER.info("已删除域名块：%s", target.get("record_name") or target_id)
    return {"ok": True}


@app.post("/api/test-token")
async def test_token(payload: Dict[str, Any], _: None = Depends(require_auth)) -> Dict[str, Any]:
    settings = store.get_settings()
    token = str(payload.get("cf_token") or "").strip()
    if not token or _masked(token):
        token = settings.get("cf_token", "")
    zone_name = str(payload.get("zone_name") or "").strip()
    record_name = str(payload.get("record_name") or "").strip()
    record_type = str(payload.get("record_type") or "A").upper()
    if not token:
        raise HTTPException(status_code=400, detail="未提供 Token")

    client = CloudflareClient(token)
    result: Dict[str, Any] = {"ok": True}
    try:
        result["token"] = await asyncio.to_thread(client.verify_token)
        if zone_name:
            zone_id = await asyncio.to_thread(client.find_zone_id, zone_name)
            result["zone"] = {"name": zone_name, "id": zone_id}
            if record_name:
                records = await asyncio.to_thread(
                    client.list_records, zone_id, record_name, record_type
                )
                result["records"] = [
                    {"content": r.get("content"), "ttl": r.get("ttl"), "proxied": r.get("proxied")}
                    for r in records
                ]
    except CloudflareError as error:
        return JSONResponse(
            status_code=400,
            content={"ok": False, "error": str(error)},
        )
    return result


@app.post("/api/scan")
async def trigger_scan(
    payload: Optional[Dict[str, Any]] = None, _: None = Depends(require_auth)
) -> Dict[str, Any]:
    if optimizer.snapshot().get("scanning"):
        return {"ok": False, "error": "已有扫描在进行中"}
    body = payload or {}
    target_id = str(body.get("target_id") or "").strip() or None
    apply_flag: Optional[bool] = None
    if "apply" in body:
        apply_flag = bool(body.get("apply"))
    if target_id and not store.get_target(target_id):
        raise HTTPException(status_code=404, detail="域名块不存在")
    asyncio.create_task(optimizer.run_scan(target_id=target_id, trigger="manual", apply=apply_flag))
    return {"ok": True, "started": True}


@app.post("/api/refresh-dns")
async def refresh_dns(
    payload: Optional[Dict[str, Any]] = None, _: None = Depends(require_auth)
) -> Dict[str, Any]:
    body = payload or {}
    target_id = str(body.get("target_id") or "").strip() or None
    return await optimizer.refresh_dns(target_id)


def _version() -> str:
    return os.getenv("APP_VERSION", "dev")


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content={"ok": False, "error": exc.detail})
