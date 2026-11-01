"""扫描 → 决策 → 更新解析 的主流程，以及按域名块独立排期的调度器。

调度模型：
  - 每个域名块（target）有各自的 interval_minutes / auto_update / switch_margin_pct
  - 调度器每 5 秒醒一次，把所有「到期且启用」的块排成一队依次执行
  - 同一时刻只跑一个块，避免几百个并发 TLS 探测互相抢带宽把结果测歪
"""
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
class TargetState:
    scanning: bool = False
    progress: Dict[str, Any] = field(default_factory=dict)
    last_report: Optional[Dict[str, Any]] = None
    last_apply: Dict[str, Any] = field(default_factory=dict)
    dns_records: List[Dict[str, Any]] = field(default_factory=list)
    dns_checked_at: float = 0.0
    next_run_at: float = 0.0
    last_run_at: float = 0.0
    last_error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scanning": self.scanning,
            "progress": self.progress,
            "last_report": self.last_report,
            "last_apply": self.last_apply,
            "dns_records": self.dns_records,
            "dns_checked_at": self.dns_checked_at,
            "next_run_at": self.next_run_at,
            "last_run_at": self.last_run_at,
            "last_error": self.last_error,
        }


class Optimizer:
    def __init__(self, store: Store) -> None:
        self.store = store
        self.states: Dict[str, TargetState] = {}
        self.log_handler = RingLogHandler()
        self.log_handler.setFormatter(logging.Formatter("%(message)s"))
        logging.getLogger().addHandler(self.log_handler)
        self._lock = asyncio.Lock()
        self._wake = asyncio.Event()
        self._task: Optional[asyncio.Task] = None

    # ---------------- 生命周期 ----------------

    async def start(self) -> None:
        self._sync_schedule(initial=True)
        self._task = asyncio.create_task(self._loop(), name="optimizer-scheduler")
        count = len(self.store.list_targets())
        LOGGER.info("调度器已启动，共 %d 个域名块", count)

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    def state_for(self, target_id: str) -> TargetState:
        state = self.states.get(target_id)
        if state is None:
            state = TargetState()
            self.states[target_id] = state
        return state

    def reload_schedule(self) -> None:
        self._sync_schedule(initial=False)
        self._wake.set()

    def _sync_schedule(self, initial: bool) -> None:
        """按每个块的 interval 重算 next_run_at，并清理已删除块的状态。

        重算基准是「上次运行时间 + 新间隔」，所以改间隔能立刻生效；
        还没跑过的块在启动时错峰排期，避免所有块同一秒一起打。
        """
        settings = self.store.get_settings()
        enabled = bool(settings.get("schedule_enabled", True))
        targets = self.store.list_targets()
        alive_ids = {t["id"] for t in targets}
        for gone in list(self.states):
            if gone not in alive_ids:
                self.states.pop(gone, None)

        now = time.time()
        for index, target in enumerate(targets):
            state = self.state_for(target["id"])
            interval = int(target.get("interval_minutes") or 0)
            if not enabled or not target.get("enabled") or interval <= 0:
                state.next_run_at = 0
                continue
            if state.last_run_at > 0:
                state.next_run_at = max(state.last_run_at + interval * 60, now + 5)
            else:
                delay = (45 + index * 20) if initial else interval * 60
                state.next_run_at = now + delay

    async def _loop(self) -> None:
        while True:
            try:
                await self._tick()
                self._wake.clear()
                try:
                    await asyncio.wait_for(self._wake.wait(), timeout=5)
                except asyncio.TimeoutError:
                    pass
            except asyncio.CancelledError:
                raise
            except Exception as error:  # noqa: BLE001
                LOGGER.exception("调度循环异常：%s", error)
                await asyncio.sleep(15)

    async def _tick(self) -> None:
        if self._lock.locked():
            return
        settings = self.store.get_settings()
        if not settings.get("schedule_enabled", True):
            return
        now = time.time()
        due: List[Dict[str, Any]] = []
        for target in self.store.list_targets():
            state = self.state_for(target["id"])
            if not target.get("enabled"):
                continue
            if int(target.get("interval_minutes") or 0) <= 0:
                continue
            if state.next_run_at and now >= state.next_run_at and not state.scanning:
                due.append(target)
        if not due:
            return
        due.sort(key=lambda t: self.state_for(t["id"]).next_run_at)
        LOGGER.info("到期待扫描的域名块：%s", "、".join(_label(t) for t in due))
        for target in due:
            await self.run_scan(target_id=target["id"], trigger="schedule")

    # ---------------- 主流程 ----------------

    async def run_scan(
        self,
        target_id: Optional[str] = None,
        trigger: str = "manual",
        apply: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """target_id 为空时依次扫描所有启用的域名块。"""
        if self._lock.locked():
            return {"ok": False, "error": "已有扫描在进行中"}
        async with self._lock:
            if target_id:
                return await self._run_one(target_id, trigger, apply)

            targets = [t for t in self.store.list_targets() if t.get("enabled")]
            if not targets:
                return {"ok": False, "error": "没有启用的域名块"}
            results = []
            for target in targets:
                results.append(await self._run_one(target["id"], trigger, apply))
            ok_count = sum(1 for r in results if r.get("ok"))
            return {
                "ok": ok_count > 0,
                "count": len(results),
                "ok_count": ok_count,
                "results": results,
            }

    async def _run_one(
        self, target_id: str, trigger: str, apply: Optional[bool]
    ) -> Dict[str, Any]:
        settings = self.store.get_settings()
        target = self.store.get_target(target_id)
        if not target:
            return {"ok": False, "error": "域名块不存在"}

        state = self.state_for(target_id)
        label = _label(target)
        host = _resolve_host(target)

        if not host:
            state.last_error = f"「{label}」未配置记录名"
            LOGGER.error(state.last_error)
            return {"ok": False, "target_id": target_id, "error": state.last_error}

        record_type = str(target.get("record_type") or "A").upper()
        ip_version = 6 if record_type == "AAAA" else 4

        state.scanning = True
        state.progress = {"done": 0, "total": 0, "stage": "准备候选 IP"}
        state.last_error = ""
        state.last_run_at = time.time()
        LOGGER.info("开始扫描 %s（目标 %s，触发：%s）", label, host, trigger)

        def on_progress(payload: Dict[str, Any]) -> None:
            state.progress = {
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
                path=str(target.get("probe_path") or settings.get("probe_path") or "/cdn-cgi/trace"),
                extra_ips=_split_ips(target.get("extra_ips") or ""),
                min_success_rate=float(settings.get("min_success_rate") or 0.5),
                max_ttfb_ms=float(settings.get("max_ttfb_ms") or 3000),
                keep=int(target.get("keep_count") or 2),
                progress=on_progress,
            )
        except Exception as error:  # noqa: BLE001
            state.scanning = False
            state.last_error = f"「{label}」扫描异常：{error}"
            LOGGER.exception("扫描失败：%s", label)
            return {"ok": False, "target_id": target_id, "error": state.last_error}

        state.progress = {"done": 1, "total": 1, "stage": "整理结果"}
        LOGGER.info(
            "%s 扫描完成：测试 %d 个候选，可用 %d 个，耗时 %.1fs，入选 %s",
            label,
            report.tested,
            len(report.alive),
            report.duration,
            ", ".join(report.chosen) or "无",
        )

        decision = await self._decide_and_apply(
            settings,
            target,
            report,
            apply if apply is not None else bool(target.get("auto_update")),
        )

        state.last_report = report.to_dict()
        state.last_apply = decision
        state.scanning = False
        state.progress = {"done": 1, "total": 1, "stage": "完成"}
        state.last_run_at = time.time()
        if decision.get("error"):
            state.last_error = decision["error"]
        self._reschedule_after_run(target)

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
                "target_id": target_id,
                "target_label": label,
            }
        )
        return {
            "ok": True,
            "target_id": target_id,
            "report": report.to_dict(),
            "decision": decision,
        }

    def _reschedule_after_run(self, target: Dict[str, Any]) -> None:
        state = self.state_for(target["id"])
        settings = self.store.get_settings()
        interval = int(target.get("interval_minutes") or 0)
        if (
            interval > 0
            and target.get("enabled")
            and settings.get("schedule_enabled", True)
        ):
            state.next_run_at = time.time() + interval * 60
        else:
            state.next_run_at = 0

    async def _decide_and_apply(
        self,
        settings: Dict[str, Any],
        target: Dict[str, Any],
        report: ScanReport,
        apply: bool,
    ) -> Dict[str, Any]:
        label = _label(target)
        record_name = (target.get("record_name") or "").strip()
        record_type = str(target.get("record_type") or "A").upper()
        zone_name = (target.get("zone_name") or "").strip()
        keep = int(target.get("keep_count") or 2)
        margin = float(target.get("switch_margin_pct") or 0)
        min_rate = float(settings.get("min_success_rate") or 0.5)

        decision: Dict[str, Any] = {
            "applied": False,
            "reason": "",
            "wanted": report.chosen,
            "current": [],
            "mode": "apply" if apply else "dry-run",
            "target_id": target["id"],
            "target_label": label,
        }

        if not report.chosen:
            decision["reason"] = "本轮没有达标 IP，保留现有解析不动"
            LOGGER.warning("%s：%s", label, decision["reason"])
            return decision

        if not apply:
            decision["reason"] = "仅扫描模式（自动更新已关闭），未修改解析"
            LOGGER.info("%s：%s", label, decision["reason"])
            return decision

        if not zone_name or not record_name or not settings.get("cf_token"):
            decision["reason"] = "Cloudflare 配置不完整（Token / Zone / 记录名）"
            decision["error"] = decision["reason"]
            LOGGER.error("%s：%s", label, decision["reason"])
            return decision

        client = CloudflareClient(str(settings.get("cf_token")))
        state = self.state_for(target["id"])

        try:
            zone_id = await asyncio.to_thread(client.find_zone_id, zone_name)
            records = await asyncio.to_thread(
                client.list_records, zone_id, record_name, record_type
            )
        except CloudflareError as error:
            decision["error"] = str(error)
            decision["reason"] = f"读取现有解析失败：{error}"
            LOGGER.error("%s：%s", label, decision["reason"])
            return decision

        current_ips = [str(r.get("content")) for r in records]
        state.dns_records = [_slim_record(r) for r in records]
        state.dns_checked_at = time.time()
        decision["current"] = current_ips

        want = list(report.chosen)[:keep]
        stat_by_ip = {r.ip: r for r in report.results}

        def stat_of(ip: str):
            return stat_by_ip.get(ip)

        # 现任是否健康：参与本轮测试且成功率达标
        healthy_current = [
            ip
            for ip in current_ips
            if stat_of(ip) is not None and stat_of(ip).success_rate >= min_rate
        ]
        need = False
        if len(healthy_current) < min(keep, len(want)):
            need = True
            decision["reason"] = (
                f"现任可用 IP 只有 {len(healthy_current)} 个，低于目标 {min(keep, len(want))}"
            )
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
            LOGGER.info("%s：%s", label, decision["reason"])
            return decision

        try:
            summary = await asyncio.to_thread(
                client.sync_records,
                zone_name=zone_name,
                name=record_name,
                record_type=record_type,
                ips=want,
                ttl=int(target.get("record_ttl") or 300),
                proxied=bool(target.get("record_proxied")),
            )
        except CloudflareError as error:
            decision["error"] = str(error)
            decision["reason"] = f"更新解析失败：{error}"
            LOGGER.error("%s：%s", label, decision["reason"])
            return decision

        decision.update(
            {
                "applied": True,
                "summary": summary,
                "final": summary.get("final"),
            }
        )
        LOGGER.info(
            "已更新 %s：新增 %s，删除 %s，保留 %s",
            record_name,
            summary.get("created") or "无",
            summary.get("deleted") or "无",
            summary.get("kept") or "无",
        )
        state.dns_records = [
            {
                "content": ip,
                "ttl": int(target.get("record_ttl") or 300),
                "proxied": bool(target.get("record_proxied")),
            }
            for ip in summary.get("final") or []
        ]
        state.dns_checked_at = time.time()
        return decision

    # ---------------- 供 HTTP 层调用的辅助 ----------------

    async def refresh_dns(self, target_id: Optional[str] = None) -> Dict[str, Any]:
        settings = self.store.get_settings()
        token = str(settings.get("cf_token") or "")
        if not token:
            return {"ok": False, "error": "未配置 Cloudflare API Token"}

        if target_id:
            targets = [t for t in [self.store.get_target(target_id)] if t]
            if not targets:
                return {"ok": False, "error": "域名块不存在"}
        else:
            targets = self.store.list_targets()
            if not targets:
                return {"ok": False, "error": "还没有域名块"}

        client = CloudflareClient(token)
        results = []
        for target in targets:
            label = _label(target)
            zone_name = (target.get("zone_name") or "").strip()
            record_name = (target.get("record_name") or "").strip()
            record_type = str(target.get("record_type") or "A").upper()
            state = self.state_for(target["id"])
            if not zone_name or not record_name:
                results.append({"id": target["id"], "ok": False, "error": f"「{label}」配置不完整"})
                continue
            try:
                zone_id = await asyncio.to_thread(client.find_zone_id, zone_name)
                records = await asyncio.to_thread(
                    client.list_records, zone_id, record_name, record_type
                )
            except CloudflareError as error:
                state.last_error = f"「{label}」读取解析失败：{error}"
                results.append({"id": target["id"], "ok": False, "error": str(error)})
                continue
            state.dns_records = [_slim_record(r) for r in records]
            state.dns_checked_at = time.time()
            results.append({"id": target["id"], "ok": True, "records": state.dns_records})

        failed = [r for r in results if not r.get("ok")]
        return {
            "ok": not failed,
            "results": results,
            "error": failed[0]["error"] if failed else "",
        }

    def snapshot(self) -> Dict[str, Any]:
        targets = self.store.list_targets()
        per_target: Dict[str, Any] = {}
        scanning_any = False
        next_ats: List[float] = []
        for target in targets:
            state = self.state_for(target["id"])
            per_target[target["id"]] = state.to_dict()
            scanning_any = scanning_any or state.scanning
            if state.next_run_at:
                next_ats.append(state.next_run_at)
        return {
            "scanning": scanning_any or self._lock.locked(),
            "targets": per_target,
            "next_run_at": min(next_ats) if next_ats else 0,
            "now": time.time(),
        }


def _label(target: Dict[str, Any]) -> str:
    return (
        str(target.get("label") or "").strip()
        or str(target.get("record_name") or "").strip()
        or "未命名的域名块"
    )


def _resolve_host(target: Dict[str, Any]) -> str:
    return str(target.get("probe_host") or target.get("record_name") or "").strip()


def _slim_record(record: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": record.get("id"),
        "content": record.get("content"),
        "ttl": record.get("ttl"),
        "proxied": record.get("proxied"),
        "comment": record.get("comment"),
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
