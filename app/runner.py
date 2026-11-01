"""扫描 → 决策 → 更新解析 的主流程，以及内存状态与日志缓冲。"""
from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Optional

from .cloudflare import CloudflareClient, CloudflareError
from .scanner import ScanReport, scan
from .store import Store

LOGGER = logging.getLogger("cfip")


class RingLogHandler(logging.Handler):
    def __init__(self, capacity: int = 500) -> None:
        super().__init__()
        self.buffer: Deque[Dict[str, Any]] = deque(maxlen=capacity)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.buffer.append(
                {
                    "ts": record.created,
                    "level": record.levelname,
                    "message": self.format(record),
                }
            )
        except Exception:
            pass

    def snapshot(self, limit: int = 200) -> List[Dict[str, Any]]:
        return list(self.buffer)[-limit:]


@dataclass
class State:
    scanning: bool = False
    progress: Dict[str, Any] = field(default_factory=dict)
    last_report: Optional[Dict[str, Any]] = None
    last_apply: Dict[str, Any] = field(default_factory=dict)
    dns_records: List[Dict[str, Any]] = field(default_factory=list)
    dns_checked_at: float = 0.0
    next_run_at: float = 0.0
    last_run_at: float = 0.0
    last_error: str = ""


class Optimizer:
    def __init__(self, store: Store) -> None:
        self.store = store
        self.state = State()
        self.log_handler = RingLogHandler()
        self.log_handler.setFormatter(logging.Formatter("%(message)s"))
        logging.getLogger().addHandler(self.log_handler)
        self._lock = asyncio.Lock()
        self._wake = asyncio.Event()
        self._task: Optional[asyncio.Task] = None

    # ---------------- 生命周期 ----------------

    async def start(self) -> None:
        settings = self.store.get_settings()
        self._schedule_next(settings, initial=True)
        self._task = asyncio.create_task(self._loop(), name="optimizer-scheduler")
        LOGGER.info("调度器已启动，下次扫描：%s", _fmt_ts(self.state.next_run_at))

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    def reload_schedule(self) -> None:
        self._schedule_next(self.store.get_settings(), initial=False)
        self._wake.set()

    def _schedule_next(self, settings: Dict[str, Any], initial: bool) -> None:
        interval = int(settings.get("interval_minutes") or 0)
        now = time.time()
        if interval <= 0:
            self.state.next_run_at = 0
            return
        self.state.next_run_at = now + (45 if initial else interval * 60)

    async def _loop(self) -> None:
        while True:
            try:
                now = time.time()
                due = self.state.next_run_at and now >= self.state.next_run_at
                if due and not self.state.scanning:
                    await self.run_scan(trigger="schedule")
                    self._schedule_next(self.store.get_settings(), initial=False)
                self._wake.clear()
                try:
                    await asyncio.wait_for(self._wake.wait(), timeout=10)
                except asyncio.TimeoutError:
                    pass
            except asyncio.CancelledError:
                raise
            except Exception as error:  # noqa: BLE001
                LOGGER.exception("调度循环异常：%s", error)
                await asyncio.sleep(15)

    # ---------------- 主流程 ----------------

    async def run_scan(self, trigger: str = "manual", apply: Optional[bool] = None) -> Dict[str, Any]:
        if self._lock.locked():
            return {"ok": False, "error": "已有扫描在进行中"}
        async with self._lock:
            settings = self.store.get_settings()
            host = (settings.get("probe_host") or settings.get("record_name") or "").strip()
            record_name = (settings.get("record_name") or "").strip()
            if not host:
                host = record_name
            if not host:
                self.state.last_error = "未配置要探测的域名"
                LOGGER.error(self.state.last_error)
                return {"ok": False, "error": self.state.last_error}

            self.state.scanning = True
            self.state.progress = {"done": 0, "total": 0, "stage": "准备候选 IP"}
            self.state.last_error = ""
            self.state.last_run_at = time.time()
            LOGGER.info("开始扫描：目标 %s，触发方式 %s", host, trigger)

            record_type = str(settings.get("record_type") or "A").upper()
            ip_version = 6 if record_type == "AAAA" else 4

            def on_progress(payload: Dict[str, Any]) -> None:
                self.state.progress = {
                    "done": payload["done"],
                    "total": payload["total"],
                    "stage": "探测中",
                }

            try:
                report = await scan(
                    host=host,
                    ip_version=ip_version,
                    candidate_count=int(settings.get("candidate_count") or 200),
                    rounds=int(settings.get("sample_rounds") or 2),
                    concurrency=int(settings.get("concurrency") or 48),
                    timeout=float(settings.get("timeout") or 4.0),
                    port=int(settings.get("probe_port") or 443),
                    path=str(settings.get("probe_path") or "/cdn-cgi/trace"),
                    extra_ips=_split_ips(settings.get("extra_ips") or ""),
                    min_success_rate=float(settings.get("min_success_rate") or 0.5),
                    max_ttfb_ms=float(settings.get("max_ttfb_ms") or 3000),
                    keep=int(settings.get("keep_count") or 2),
                    progress=on_progress,
                )
            except Exception as error:  # noqa: BLE001
                self.state.scanning = False
                self.state.last_error = f"扫描异常：{error}"
                LOGGER.exception("扫描失败")
                return {"ok": False, "error": self.state.last_error}

            self.state.progress = {"done": 1, "total": 1, "stage": "整理结果"}
            LOGGER.info(
                "扫描完成：测试 %d 个候选，可用 %d 个，耗时 %.1fs，入选 %s",
                report.tested,
                len(report.alive),
                report.duration,
                ", ".join(report.chosen) or "无",
            )

            decision = await self._decide_and_apply(
                settings, report, apply if apply is not None else bool(settings.get("auto_update"))
            )

            self.state.last_report = report.to_dict()
            self.state.last_apply = decision
            self.state.scanning = False
            self.state.progress = {"done": 1, "total": 1, "stage": "完成"}
            self.state.last_run_at = time.time()

            self.store.add_scan(
                {
                    "started_at": report.started_at,
                    "finished_at": report.finished_at,
                    "trigger": trigger,
                    "tested": report.tested,
                    "alive": len(report.alive),
                    "chosen": report.chosen,
                    "applied": decision,
                    "applied_at_all": bool(decision.get("applied")),
                    "detail": [r.to_dict() for r in report.results[:50]],
                    "error": decision.get("error") or "",
                }
            )
            return {"ok": True, "report": report.to_dict(), "decision": decision}

    async def _decide_and_apply(
        self, settings: Dict[str, Any], report: ScanReport, apply: bool
    ) -> Dict[str, Any]:
        record_name = (settings.get("record_name") or "").strip()
        record_type = str(settings.get("record_type") or "A").upper()
        zone_name = (settings.get("zone_name") or "").strip()
        keep = int(settings.get("keep_count") or 2)
        margin = float(settings.get("switch_margin_pct") or 15)

        decision: Dict[str, Any] = {
            "applied": False,
            "reason": "",
            "wanted": report.chosen,
            "current": [],
            "mode": "apply" if apply else "dry-run",
        }

        if not report.chosen:
            decision["reason"] = "本轮没有达标 IP，保留现有解析不动"
            LOGGER.warning(decision["reason"])
            return decision

        if not apply:
            decision["reason"] = "仅扫描模式（auto_update 已关闭），未修改解析"
            LOGGER.info(decision["reason"])
            return decision

        if not zone_name or not record_name or not settings.get("cf_token"):
            decision["reason"] = "Cloudflare 配置不完整（Token / Zone / 记录名）"
            decision["error"] = decision["reason"]
            LOGGER.error(decision["reason"])
            return decision

        client = CloudflareClient(str(settings.get("cf_token")))

        try:
            zone_id = await asyncio.to_thread(client.find_zone_id, zone_name)
            records = await asyncio.to_thread(
                client.list_records, zone_id, record_name, record_type
            )
        except CloudflareError as error:
            decision["error"] = str(error)
            decision["reason"] = f"读取现有解析失败：{error}"
            LOGGER.error(decision["reason"])
            return decision

        current_ips = [str(r.get("content")) for r in records]
        self.state.dns_records = [
            {
                "id": r.get("id"),
                "content": r.get("content"),
                "ttl": r.get("ttl"),
                "proxied": r.get("proxied"),
                "comment": r.get("comment"),
            }
            for r in records
        ]
        self.state.dns_checked_at = time.time()
        decision["current"] = current_ips

        want = list(report.chosen)[:keep]
        stat_by_ip = {r.ip: r for r in report.results}

        def stat_of(ip: str):
            return stat_by_ip.get(ip)

        # 现任是否健康：参与本轮测试且成功率达标
        healthy_current = [
            ip
            for ip in current_ips
            if (stat_of(ip) is not None and stat_of(ip).success_rate >= float(settings.get("min_success_rate") or 0.5))
        ]
        need = False
        if len(healthy_current) < min(keep, len(want)):
            need = True
            decision["reason"] = f"现任可用 IP 只有 {len(healthy_current)} 个，低于目标 {min(keep, len(want))}"
        elif set(want) != set(current_ips):
            best_current = min(
                (stat_of(ip).ttfb_ms for ip in healthy_current if stat_of(ip)),
                default=9e9,
            )
            best_new = min(
                (stat_of(ip).ttfb_ms for ip in want if stat_of(ip)),
                default=9e9,
            )
            if best_new <= best_current * (1 - margin / 100.0):
                need = True
                decision["reason"] = (
                    f"新 IP 更快：{best_new:.0f}ms vs 现任 {best_current:.0f}ms"
                    f"（超过 {margin:.0f}% 阈值）"
                )
            else:
                decision["reason"] = (
                    f"新 IP 未明显优于现任（{best_new:.0f}ms vs {best_current:.0f}ms），保持不动"
                )
        else:
            decision["reason"] = "现任 IP 与本轮最优一致，无需变更"

        if not need:
            LOGGER.info(decision["reason"])
            return decision

        try:
            summary = await asyncio.to_thread(
                client.sync_records,
                zone_name=zone_name,
                name=record_name,
                record_type=record_type,
                ips=want,
                ttl=int(settings.get("record_ttl") or 300),
                proxied=bool(settings.get("record_proxied")),
            )
        except CloudflareError as error:
            decision["error"] = str(error)
            decision["reason"] = f"更新解析失败：{error}"
            LOGGER.error(decision["reason"])
            return decision

        decision.update(
            {
                "applied": True,
                "summary": summary,
                "final": summary.get("final"),
            }
        )
        LOGGER.info(
            "已更新解析 %s：新增 %s，删除 %s，保留 %s",
            record_name,
            summary.get("created") or "无",
            summary.get("deleted") or "无",
            summary.get("kept") or "无",
        )
        self.state.dns_records = [
            {"content": ip, "ttl": int(settings.get("record_ttl") or 300),
             "proxied": bool(settings.get("record_proxied"))}
            for ip in summary.get("final") or []
        ]
        self.state.dns_checked_at = time.time()
        return decision

    # ---------------- 供 HTTP 层调用的辅助 ----------------

    async def refresh_dns(self) -> Dict[str, Any]:
        settings = self.store.get_settings()
        zone_name = (settings.get("zone_name") or "").strip()
        record_name = (settings.get("record_name") or "").strip()
        record_type = str(settings.get("record_type") or "A").upper()
        if not (settings.get("cf_token") and zone_name and record_name):
            return {"ok": False, "error": "Cloudflare 配置不完整"}
        client = CloudflareClient(str(settings.get("cf_token")))
        try:
            zone_id = await asyncio.to_thread(client.find_zone_id, zone_name)
            records = await asyncio.to_thread(
                client.list_records, zone_id, record_name, record_type
            )
        except CloudflareError as error:
            return {"ok": False, "error": str(error)}
        self.state.dns_records = [
            {
                "id": r.get("id"),
                "content": r.get("content"),
                "ttl": r.get("ttl"),
                "proxied": r.get("proxied"),
                "comment": r.get("comment"),
            }
            for r in records
        ]
        self.state.dns_checked_at = time.time()
        return {"ok": True, "records": self.state.dns_records}

    def snapshot(self) -> Dict[str, Any]:
        return {
            "scanning": self.state.scanning,
            "progress": self.state.progress,
            "last_report": self.state.last_report,
            "last_apply": self.state.last_apply,
            "dns_records": self.state.dns_records,
            "dns_checked_at": self.state.dns_checked_at,
            "next_run_at": self.state.next_run_at,
            "last_run_at": self.state.last_run_at,
            "last_error": self.state.last_error,
            "now": time.time(),
        }


def _split_ips(raw: str) -> List[str]:
    parts: List[str] = []
    for line in str(raw).splitlines():
        for token in line.replace(",", " ").split():
            token = token.strip()
            if token:
                parts.append(token)
    return parts


def _fmt_ts(ts: float) -> str:
    if not ts:
        return "未排期"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
