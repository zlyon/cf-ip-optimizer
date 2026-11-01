"""Cloudflare API v4 客户端（仅 DNS 相关能力）。"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Sequence

import requests

API_BASE = "https://api.cloudflare.com/client/v4"
MANAGED_COMMENT = "managed by cf-ip-optimizer"


class CloudflareError(RuntimeError):
    def __init__(self, message: str, status: Optional[int] = None, errors: Any = None):
        super().__init__(message)
        self.status = status
        self.errors = errors or []


class CloudflareClient:
    def __init__(self, token: str, timeout: float = 20.0):
        token = (token or "").strip()
        if not token:
            raise CloudflareError("未配置 Cloudflare API Token")
        self.token = token
        self.timeout = timeout
        self.session = requests.Session()
        # 容器内通常无代理；显式信任环境变量会让 NAS 上的 http_proxy 干扰，
        # 这里保持 False 更可预期。
        self.session.trust_env = False
        self.session.headers.update(
            {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "User-Agent": "cf-ip-optimizer/1.0",
            }
        )

    # ---------------- 基础请求 ----------------

    def _request(self, method: str, path: str, **kwargs) -> Any:
        url = f"{API_BASE}{path}"
        try:
            response = self.session.request(
                method, url, timeout=self.timeout, **kwargs
            )
        except requests.RequestException as error:
            raise CloudflareError(f"请求 Cloudflare 失败：{type(error).__name__}") from error

        try:
            payload = response.json()
        except ValueError:
            raise CloudflareError(
                f"Cloudflare 返回非 JSON（HTTP {response.status_code}）",
                status=response.status_code,
            )

        if not payload.get("success"):
            errors = payload.get("errors") or []
            message = "；".join(
                str(item.get("message") or item) for item in errors
            ) or f"HTTP {response.status_code}"
            raise CloudflareError(message, status=response.status_code, errors=errors)
        return payload.get("result")

    # ---------------- token / zone ----------------

    def verify_token(self) -> Dict[str, Any]:
        try:
            result = self._request("GET", "/user/tokens/verify")
            return {"ok": True, "status": (result or {}).get("status", "active")}
        except CloudflareError as error:
            # 部分 Account 级 Token 无 /user 权限，退一步用 zones 列表判断
            try:
                zones = self._request("GET", "/zones", params={"per_page": 1})
                return {"ok": True, "status": "active", "note": "token 无 /user 权限，已用 zones 验证"}
            except CloudflareError:
                raise error

    def find_zone_id(self, zone_name: str) -> str:
        zone_name = (zone_name or "").strip().rstrip(".")
        if not zone_name:
            raise CloudflareError("未配置 Zone 名称")
        zones = self._request(
            "GET", "/zones", params={"name": zone_name, "per_page": 50}
        ) or []
        for zone in zones:
            if str(zone.get("name", "")).lower() == zone_name.lower():
                return str(zone["id"])
        # 兜底：可能是子域填错，列出账号下所有 zone 方便排查
        available = ", ".join(str(z.get("name")) for z in zones[:10]) or "无"
        raise CloudflareError(
            f"Token 中找不到 Zone「{zone_name}」，可见的 Zone：{available}"
        )

    # ---------------- DNS 记录 ----------------

    def list_records(
        self, zone_id: str, name: str, record_type: str
    ) -> List[Dict[str, Any]]:
        records = self._request(
            "GET",
            f"/zones/{zone_id}/dns_records",
            params={"type": record_type, "name": name, "per_page": 100},
        ) or []
        return [
            r
            for r in records
            if str(r.get("name", "")).lower() == name.lower()
            and str(r.get("type", "")).upper() == record_type.upper()
        ]

    def create_record(
        self,
        zone_id: str,
        name: str,
        record_type: str,
        content: str,
        ttl: int,
        proxied: bool,
    ) -> Dict[str, Any]:
        body = {
            "type": record_type,
            "name": name,
            "content": content,
            "ttl": max(1, int(ttl)),
            "proxied": bool(proxied) and record_type.upper() in ("A", "AAAA", "CNAME"),
            "comment": MANAGED_COMMENT,
        }
        return self._request("POST", f"/zones/{zone_id}/dns_records", json=body)

    def update_record(
        self,
        zone_id: str,
        record_id: str,
        *,
        content: str,
        ttl: int,
        proxied: bool,
        record_type: str,
    ) -> Dict[str, Any]:
        body = {
            "content": content,
            "ttl": max(1, int(ttl)),
            "proxied": bool(proxied) and record_type.upper() in ("A", "AAAA", "CNAME"),
            "comment": MANAGED_COMMENT,
        }
        return self._request(
            "PATCH", f"/zones/{zone_id}/dns_records/{record_id}", json=body
        )

    def delete_record(self, zone_id: str, record_id: str) -> Any:
        return self._request("DELETE", f"/zones/{zone_id}/dns_records/{record_id}")

    def find_conflicting_cname(
        self, zone_id: str, name: str, record_type: str
    ) -> Optional[Dict[str, Any]]:
        """A/AAAA 与 CNAME 不能同名共存，改记录前先查一下有没有 CNAME 挡路。"""
        if record_type.upper() not in ("A", "AAAA"):
            return None
        records = self._request(
            "GET",
            f"/zones/{zone_id}/dns_records",
            params={"name": name, "per_page": 100},
        ) or []
        for record in records:
            if (
                str(record.get("name", "")).lower() == name.lower()
                and str(record.get("type", "")).upper() == "CNAME"
            ):
                return record
        return None

    def sync_records(
        self,
        *,
        zone_name: str,
        name: str,
        record_type: str,
        ips: Sequence[str],
        ttl: int = 300,
        proxied: bool = False,
    ) -> Dict[str, Any]:
        """把指定 name/type 的记录集合同步成 ips。

        只增删差异，不动其他记录；ips 为空时抛错，避免把唯一入口删干净。
        """
        wanted = [ip for ip in dict.fromkeys(ips) if ip]
        if not wanted:
            raise CloudflareError("目标 IP 列表为空，已跳过更新以防断服")

        zone_id = self.find_zone_id(zone_name)

        conflict = self.find_conflicting_cname(zone_id, name, record_type)
        if conflict is not None:
            raise CloudflareError(
                f"「{name}」当前是 CNAME 记录（指向 {conflict.get('content')}）。"
                "Cloudflare 不允许同名 CNAME 与 A/AAAA 记录并存，"
                "请先在 DNS 页面删除这条 CNAME（并确认 Worker 的 Route 已配好）再运行。"
            )

        current = self.list_records(zone_id, name, record_type)
        current_by_ip = {str(r.get("content")): r for r in current}

        created: List[str] = []
        updated: List[str] = []
        deleted: List[str] = []
        kept: List[str] = []

        for ip in wanted:
            existing = current_by_ip.get(ip)
            if existing is None:
                self.create_record(zone_id, name, record_type, ip, ttl, proxied)
                created.append(ip)
                continue
            wants_change = (
                int(existing.get("ttl", 0) or 0) != int(ttl)
                or bool(existing.get("proxied")) != bool(proxied and record_type != "TXT")
            )
            if wants_change:
                self.update_record(
                    zone_id,
                    str(existing["id"]),
                    content=ip,
                    ttl=ttl,
                    proxied=proxied,
                    record_type=record_type,
                )
                updated.append(ip)
            else:
                kept.append(ip)

        for ip, record in current_by_ip.items():
            if ip in wanted:
                continue
            self.delete_record(zone_id, str(record["id"]))
            deleted.append(ip)

        return {
            "zone_id": zone_id,
            "created": created,
            "updated": updated,
            "deleted": deleted,
            "kept": kept,
            "final": wanted,
        }
