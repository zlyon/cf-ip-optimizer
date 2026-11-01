"""Cloudflare 边缘 IP 探测与优选。

直接用 asyncio + 原生 TLS 握手打目标 IP，不走系统代理（不读 http_proxy 等
环境变量），所以测出来的就是本机到该 IP 的真实链路质量。

评分口径：
  - 每一轮成功 = TLS 握手 + HTTP 响应首字节 + 响应体完整传完
  - 只读到响应头不算成功：优选 IP 的典型故障是「握手快、首包快、正文丢包」，
    只按首字节判定会把这类 IP 排到第一位
  - 业务路径优先：/cdn-cgi/trace 由 CF 边缘自己应答，不经过 Worker/源站，
    用它探不出「边缘正常但业务路由 403」的 IP，默认探 /
  - ttfb 取多轮中位数（比平均值抗抖动）
  - 成功率优先于速度排序：一次 8 秒超时比慢 300ms 致命得多
"""
from __future__ import annotations

import asyncio
import ipaddress
import random
import socket
import ssl
import statistics
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence

# Cloudflare 官方公布的边缘网段（https://www.cloudflare.com/ips/）
CF_IPV4_SEGMENTS: Sequence[str] = (
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
)

CF_IPV6_SEGMENTS: Sequence[str] = (
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
)

USER_AGENT = "cf-ip-optimizer/1.0"

# Cloudflare 并非所有 anycast IP 都能用来承载「灰云记录」的回源：
# 落在受限 IP 上时边缘直接返回 403 + "error code: 1034"（Edge IP Restricted）。
#
# 这类 IP 的握手往往比正常 IP 还快（0.4s 就吐完错误页），如果只按「有没有收到
# 响应首字节」判定成功，它会被排到第一位并写进解析——之后命中它的请求全部失败，
# 且因为同一记录里还有正常 IP，表现出来就是「时好时坏」，极难定位。
# 所以必须按状态码 + CF 错误标记判死，而不是只看通不通。
_CF_BLOCK_SIGNATURES = (
    ("error code: 1034", "边缘拒绝 1034"),
    ("error code: 1010", "边缘拦截 1010"),
    ("edge ip restricted", "边缘拒绝 1034"),
    ("error code: 1003", "边缘拒绝 1003"),
)

# CF 自己吐的错误页特征。命中说明请求根本没到业务路由（Worker/源站），
# 而是被边缘挡下了 —— 这种 IP 装进解析后，命中它的请求 100% 失败。
_CF_ERROR_PAGE_MARKERS = (
    "<center>cloudflare</center>",
    "cf-error-details",
    "/cdn-cgi/images/trace/",
    "cloudflare ray id",
)


def _detect_cf_block(status: int, headers: Dict[str, str], body: bytes) -> str:
    """识别「CF 边缘拒绝服务这个主机」的响应，返回原因；正常响应返回空串。"""
    if status not in (403, 451):
        return ""
    text = body.decode("utf-8", "replace").lower()
    for signature, label in _CF_BLOCK_SIGNATURES:
        if signature in text:
            return label
    if headers.get("cf-mitigated"):
        return f"边缘拒绝 {status}"
    # 例如 172.65.212.5：trace 200 且很快，但业务路径返回 CF 标准 403 错误页。
    # 旧逻辑要求正文同时出现 cloudflare + error，而该页只有 403 Forbidden，
    # 于是被当成健康 IP 选进解析。
    if any(marker in text for marker in _CF_ERROR_PAGE_MARKERS):
        return f"边缘拒绝 {status}"
    if "cloudflare" in text and "error" in text:
        return f"边缘拒绝 {status}"
    return ""


@dataclass
class IPStat:
    ip: str
    ok: int = 0
    total: int = 0
    ttfb_samples: List[float] = field(default_factory=list)
    handshake_samples: List[float] = field(default_factory=list)
    colo: str = ""
    last_error: str = ""
    status: int = 0
    blocked: str = ""  # 非空表示被 CF 边缘拒绝，绝不能写进解析

    @property
    def success_rate(self) -> float:
        return self.ok / self.total if self.total else 0.0

    @property
    def ttfb_ms(self) -> float:
        return statistics.median(self.ttfb_samples) if self.ttfb_samples else 0.0

    @property
    def handshake_ms(self) -> float:
        return statistics.median(self.handshake_samples) if self.handshake_samples else 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "ok": self.ok,
            "total": self.total,
            "success_rate": round(self.success_rate, 3),
            "ttfb_ms": round(self.ttfb_ms, 1),
            "handshake_ms": round(self.handshake_ms, 1),
            "colo": self.colo,
            "status": self.status,
            "blocked": self.blocked,
            "last_error": self.last_error,
        }


@dataclass
class ScanReport:
    started_at: float
    finished_at: float
    tested: int
    results: List[IPStat]
    chosen: List[str]
    errors: List[str] = field(default_factory=list)

    @property
    def duration(self) -> float:
        return self.finished_at - self.started_at

    @property
    def alive(self) -> List[IPStat]:
        return [r for r in self.results if r.ok > 0]

    @property
    def blocked(self) -> List[IPStat]:
        return [r for r in self.results if r.blocked]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration": round(self.duration, 1),
            "tested": self.tested,
            "alive": len(self.alive),
            "blocked": len(self.blocked),
            "chosen": self.chosen,
            "results": [r.to_dict() for r in self.results],
            "errors": self.errors,
        }


def _random_ip_in(net: ipaddress._BaseNetwork, rng: random.Random) -> str:
    base = int(net.network_address)
    size = net.num_addresses
    if net.version == 4:
        return str(ipaddress.IPv4Address(base + rng.randrange(1, max(2, size - 1))))
    # IPv6：固定前 32 位（Cloudflare 分配段），随机后 96 位
    return str(ipaddress.IPv6Address(base + rng.getrandbits(96)))


def sample_candidates(
    limit: int,
    ip_version: int = 4,
    extra: Iterable[str] = (),
    rng: Optional[random.Random] = None,
) -> List[str]:
    """在官方网段内随机采样候选 IP，并合并用户自定义 IP。"""
    rng = rng or random.Random()
    segments = CF_IPV4_SEGMENTS if ip_version == 4 else CF_IPV6_SEGMENTS
    nets = [ipaddress.ip_network(s) for s in segments]

    picked: List[str] = []
    seen = set()

    for raw in extra:
        token = str(raw).strip()
        if not token or token.startswith("#"):
            continue
        # 允许出现 CIDR，展开成最多 8 个采样点
        if "/" in token:
            try:
                net = ipaddress.ip_network(token, strict=False)
            except ValueError:
                continue
            want = min(8, max(1, net.num_addresses - 2))
            added = 0
            tries = 0
            while added < want and tries < want * 40:
                tries += 1
                ip = _random_ip_in(net, rng)
                if ip in seen:
                    continue
                seen.add(ip)
                picked.append(ip)
                added += 1
            continue
        try:
            ipaddress.ip_address(token)
        except ValueError:
            continue
        if token not in seen:
            seen.add(token)
            picked.append(token)

    budget = max(0, limit - len(picked))
    if budget:
        # 随机挑段，保证候选均匀散布在所有网段而不是堆在前几个 /20 里
        attempts = 0
        while budget > 0 and attempts < limit * 30:
            attempts += 1
            net = rng.choice(nets)
            ip = _random_ip_in(net, rng)
            if ip in seen:
                continue
            seen.add(ip)
            picked.append(ip)
            budget -= 1
    return picked[: max(limit, len(picked))]


def _parse_colo(headers: Dict[str, str], body: bytes) -> str:
    ray = headers.get("cf-ray", "")
    if "-" in ray:
        suffix = ray.rsplit("-", 1)[-1].strip().upper()
        if len(suffix) == 3 and suffix.isalpha():
            return suffix
    if body:
        try:
            text = body.decode("utf-8", "replace")
        except Exception:
            return ""
        for line in text.splitlines():
            if line.startswith("colo="):
                return line.split("=", 1)[1].strip().upper()[:3]
    return ""


async def _probe_once(
    ip: str,
    host: str,
    port: int,
    path: str,
    timeout: float,
    max_body: int = 16384,
    tls: bool = True,
) -> Dict[str, Any]:
    """对单个 IP 做一次 TLS + HTTP 探测。tls=False 仅供自测用明文端口。"""
    started = time.perf_counter()
    writer: Optional[asyncio.StreamWriter] = None
    try:
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            connect = asyncio.open_connection(
                host=ip,
                port=port,
                ssl=ctx,
                server_hostname=host,
                family=family,
            )
        else:
            connect = asyncio.open_connection(host=ip, port=port, family=family)
        reader, writer = await asyncio.wait_for(connect, timeout=timeout)
        handshake_ms = (time.perf_counter() - started) * 1000

        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {USER_AGENT}\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        )
        first_byte_at = time.perf_counter()
        writer.write(request.encode("latin-1"))
        await asyncio.wait_for(writer.drain(), timeout=timeout)

        raw_head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=timeout)
        ttfb_ms = (time.perf_counter() - first_byte_at) * 1000

        lines = raw_head.decode("latin-1", "replace").split("\r\n")
        status = 0
        parts = lines[0].split()
        if len(parts) >= 2 and parts[1].isdigit():
            status = int(parts[1])
        if status == 0:
            return {"ok": False, "error": "响应无状态行", "handshake_ms": handshake_ms}

        headers: Dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()

        try:
            body_head = await asyncio.wait_for(reader.read(2048), timeout=min(2.0, timeout))
        except Exception:
            body_head = b""

        blocked = _detect_cf_block(status, headers, body_head)
        if blocked:
            # 能收到响应但被边缘拒绝服务，等同于不可用；记录原因供页面展示。
            return {
                "ok": False,
                "handshake_ms": handshake_ms,
                "ttfb_ms": ttfb_ms,
                "colo": _parse_colo(headers, body_head),
                "status": status,
                "blocked": blocked,
                "error": blocked,
            }

        if status >= 500:
            # 5xx 不是 CF 错误页也算不可用：业务路由/源站此刻是坏的，
            # 装进解析只会把故障平摊到 1/N 的请求上。
            return {
                "ok": False,
                "handshake_ms": handshake_ms,
                "ttfb_ms": ttfb_ms,
                "colo": _parse_colo(headers, body_head),
                "status": status,
                "blocked": "",
                "error": f"服务端 {status}",
            }

        # 读完整响应体。优选 IP 最典型的隐性故障是「首包秒回、正文拉不动」，
        # 只读到首部就判成功会让这类 IP 拿到很高的排名。
        body = body_head
        complete = True
        expected = 0
        try:
            expected = int(headers.get("content-length") or 0)
        except ValueError:
            expected = 0
        if expected and len(body) >= expected:
            complete = True
        else:
            deadline = time.perf_counter() + timeout
            try:
                while len(body) < max_body:
                    remain = deadline - time.perf_counter()
                    if remain <= 0:
                        complete = False
                        break
                    chunk = await asyncio.wait_for(reader.read(8192), timeout=remain)
                    if not chunk:
                        break
                    body += chunk
            except asyncio.TimeoutError:
                complete = False
            except (ConnectionResetError, OSError):
                complete = False

        if not complete:
            return {
                "ok": False,
                "handshake_ms": handshake_ms,
                "ttfb_ms": ttfb_ms,
                "colo": _parse_colo(headers, body_head),
                "status": status,
                "blocked": "",
                "error": f"响应体未传完（已收 {len(body)} 字节）",
            }

        return {
            "ok": True,
            "handshake_ms": handshake_ms,
            "ttfb_ms": ttfb_ms,
            "colo": _parse_colo(headers, body),
            "status": status,
            "blocked": "",
            "error": "",
        }
    except asyncio.TimeoutError:
        return {"ok": False, "error": "超时", "handshake_ms": 0.0}
    except (ssl.SSLError, ConnectionResetError, OSError) as error:
        return {
            "ok": False,
            "error": f"{type(error).__name__}: {error}"[:120],
            "handshake_ms": 0.0,
        }
    except Exception as error:  # noqa: BLE001 - 任何异常都不该中断整轮扫描
        return {
            "ok": False,
            "error": f"{type(error).__name__}: {error}"[:120],
            "handshake_ms": 0.0,
        }
    finally:
        if writer is not None:
            try:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
            except Exception:
                pass


def select_qualified(
    results: Sequence[IPStat],
    *,
    min_success_rate: float = 0.5,
    max_ttfb_ms: float = 3000,
    keep: int = 2,
) -> List[str]:
    """按「成功率优先、延迟次之」挑出可写进解析的 IP。

    被 CF 边缘拒绝的 IP 即使收到了响应也不算数：它的握手可能很快，但装上之后
    命中它的请求会 100% 失败。
    """
    qualified = [
        s
        for s in results
        if s.ok > 0
        and not s.blocked
        and s.success_rate >= min_success_rate
        and (max_ttfb_ms <= 0 or s.ttfb_ms <= max_ttfb_ms)
    ]
    return [s.ip for s in qualified[: max(1, keep)]]


async def scan(
    *,
    host: str,
    ip_version: int = 4,
    candidate_count: int = 200,
    rounds: int = 2,
    concurrency: int = 48,
    timeout: float = 4.0,
    port: int = 443,
    path: str = "/",
    extra_ips: Iterable[str] = (),
    min_success_rate: float = 0.5,
    max_ttfb_ms: float = 3000,
    keep: int = 2,
    progress: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> ScanReport:
    started_at = time.time()
    candidates = sample_candidates(candidate_count, ip_version, extra_ips)
    stats: Dict[str, IPStat] = {ip: IPStat(ip=ip) for ip in candidates}

    semaphore = asyncio.Semaphore(max(1, concurrency))
    total_tasks = len(candidates) * max(1, rounds)
    done = 0
    lock = asyncio.Lock()

    async def worker(ip: str) -> None:
        nonlocal done
        async with semaphore:
            result = await _probe_once(ip, host, port, path, timeout)
        stat = stats[ip]
        stat.total += 1
        if result.get("blocked"):
            # 被边缘拒绝的 IP 一旦出现就永久标记：这是 IP 属性，不是抖动，
            # 换个时间重试同样是 1034，留在候选里只会污染排序。
            stat.blocked = result["blocked"]
            stat.status = int(result.get("status") or 0)
            stat.last_error = result["blocked"]
        elif result["ok"] and not stat.blocked:
            stat.ok += 1
            stat.status = int(result.get("status") or 0)
            stat.ttfb_samples.append(result["ttfb_ms"])
            stat.handshake_samples.append(result["handshake_ms"])
            if not stat.colo and result.get("colo"):
                stat.colo = result["colo"]
        else:
            stat.last_error = result["error"]
        async with lock:
            done += 1
            if progress and (done % 10 == 0 or done == total_tasks):
                progress({"done": done, "total": total_tasks})

    tasks = [worker(ip) for ip in candidates for _ in range(max(1, rounds))]
    if tasks:
        await asyncio.gather(*tasks)

    results = sorted(
        stats.values(),
        key=lambda s: (-s.success_rate, s.ttfb_ms or 9e9),
    )

    chosen = select_qualified(
        results,
        min_success_rate=min_success_rate,
        max_ttfb_ms=max_ttfb_ms,
        keep=keep,
    )

    return ScanReport(
        started_at=started_at,
        finished_at=time.time(),
        tested=len(candidates),
        results=results,
        chosen=chosen,
    )
