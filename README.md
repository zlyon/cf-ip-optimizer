# Cloudflare 优选 IP 自动更新

自动扫描 Cloudflare 边缘 IP，挑出**在你这条宽带上真正连得通、而且快**的那几个，通过 Cloudflare API 写回 DNS 解析。带 Web 管理页面、定时任务，Docker 一条命令部署。

给的场景很具体：域名挂在 Cloudflare，源站（或 Worker）本身没问题，但解析到的 anycast IP 在本地被阻断 / 绕远路，表现为时快时慢、动不动几十秒超时。手动扫 IP、手动改 DNS 太麻烦，所以做成定时自动跑。

---

## 功能

- **扫描**：在 Cloudflare 官方网段内随机采样候选 IP，并发做 TLS 握手 + HTTP 首字节探测，记录机房代码（`colo`）、握手耗时、首字节耗时、成功率
- **优选**：按「成功率优先、延迟次之」排序，取前 N 个；成功率低于阈值或超时的直接淘汰
- **自动更新**：通过 Cloudflare API 把 DNS 记录同步成优选结果，只增删差异，不动其他记录
- **防误切**：新 IP 必须比现任快 `switch_margin_pct`% 才换；本轮没有达标 IP 时**保留现有解析不动**，避免把自己切死
- **定时任务**：默认每 360 分钟跑一次，可在页面改；`0` 表示关闭定时
- **Web 管理**：登录保护、当前解析、扫描结果表、设置表单、运行日志实时刷新
- **多值解析**：可同时保留 2~3 条 A 记录，CF 会轮询返回，天然互为备份
- **历史记录**：最近 200 次扫描结果落库（SQLite），重启不丢

## 工作原理

```
采样候选 IP ──> 并发探测（TLS + HTTP 首字节）
                     │
                     ├─ 逐 IP 记录 colo / ttfb / 成功率
                     ▼
              排序 + 过滤（成功率、延迟阈值）
                     ▼
             取前 N 个 ──> 与现有 DNS 记录比对
                              │
                              ├─ 现任都健康且新 IP 没快够 → 不动
                              └─ 需要更新 → 调用 CF API 增删记录
```

探测是**直连 IP**（不经过系统 DNS，也不读 `http_proxy` 等环境变量），所以测出来的就是本机到该 IP 的真实链路。请求时用你配置的域名做 SNI / Host，所以探测路径和浏览器访问完全一致。

每轮探测会从 `cf-ray` 响应头取末尾的机房代码（`HKG` / `NRT` / `LAX`…），页面上直接显示，方便判断是"线路绕美西"还是"IP 被阻断"。

## 部署

### Docker Compose

```yaml
services:
  cf-ip-optimizer:
    image: ghcr.io/zlyon/cf-ip-optimizer:latest
    container_name: cf-ip-optimizer
    ports:
      - "8787:8080"
    volumes:
      - ./data:/data
    environment:
      TZ: Asia/Shanghai
    restart: unless-stopped
```

```bash
mkdir -p /volume1/docker/cf-ip-optimizer && cd /volume1/docker/cf-ip-optimizer
# 把上面的 compose 存成 docker-compose.yml
docker compose up -d
```

打开 `http://NAS_IP:8787`，首次访问会让你设置管理密码（≥8 位）。

群晖上如果 `/data` 写不进去（容器内是 UID 1000），在 compose 里加一行 `user: "你的UID:你的GID"`，或先 `chown -R 1000:1000 ./data`。

### 镜像地址

`ghcr.io/zlyon/cf-ip-optimizer`，`latest` 跟随 main 分支，也可以指定 `sha-xxxxxxx` 固定版本。amd64 / arm64 都构建了。

## 配置

### 1. 创建 Cloudflare API Token

Cloudflare 控制台 → 右上头像 → **My Profile → API Tokens → Create Token** → 用 **Custom token**：

| 权限 | 作用 |
|---|---|
| `Zone → DNS → Edit` | 读改 DNS 记录 |
| `Zone → Zone → Read` | 按名称查 Zone ID |

**Zone Resources** 选 `Include → Specific zone → 你的域名`，最小权限即可，不需要 Account 级权限。

### 2. 页面上的必填项

| 字段 | 说明 | 例子 |
|---|---|---|
| API Token | 上一步生成的 | `AbCd...` |
| Zone 名称 | 域名所在的 zone | `example.com` |
| 记录名 | 要维护的完整记录名 | `tgapi.example.com` |
| 记录类型 | `A` 或 `AAAA` | `A` |
| 保留 IP 数量 | 同时保留几条记录 | `2` |
| 代理状态 | **Worker 场景必须关闭（灰云）** | 关 |

填完先点 **测试 Token 与记录**，能看到当前记录就说明权限没问题。

### 3. 探测参数（默认值够用）

| 字段 | 默认 | 说明 |
|---|---|---|
| 探测域名 | 留空用记录名 | SNI / Host，建议就用要更新的域名 |
| 探测路径 | `/cdn-cgi/trace` | 该路径返回 `colo=`，最轻量。若被 Worker Route 拦截也无妨，会退化为从 `cf-ray` 头取机房 |
| 候选 IP 数量 | 200 | 越大越可能扫到好 IP，耗时线性增长 |
| 每 IP 采样轮数 | 2 | 2 轮可以算成功率；1 轮更快但分不清偶发丢包 |
| 并发数 | 48 | NAS 上 48 合适，网络差的宽带别调太高 |
| 单次超时 | 4 秒 | 超过即判失败 |
| 最低成功率 | 0.5 | 两轮里至少要有一轮通 |
| 最大可接受延迟 | 3000 ms | 0 表示不限 |

### 4. 调度与更新

| 字段 | 默认 | 说明 |
|---|---|---|
| 扫描间隔 | 360 分钟 | `0` 关闭定时，只手动跑 |
| 自动更新解析 | 开 | 关闭后只扫描、只报告，不动 DNS |
| 切换阈值 | 15 % | 新 IP 要比现任快 15% 以上才换，防止来回抖 |

## 使用建议

**第一次先"只扫描不更新"**，看结果表里有没有 `colo` 是 `HKG` / `NRT` / `SIN` 且延迟低的 IP。如果全是 `LAX`，说明这条宽带出口就是绕美西，优选 IP 能改善的是"避开被阻断的 IP"，改善不了物理距离。

**保留 2 条而不是 1 条**。CF 对同名多条 A 记录会轮询返回，一条挂了还有另一条；只有 1 条时，那个 IP 被阻断就等于整站不可达。

**TTL 设 300 秒左右**。太短会让 CF 调用频繁，太长切换后生效慢。

**Worker + 灰云的特殊约束**：如果你的域名是 Worker 的 Custom Domain，改优选的正确姿势是「删掉 Custom Domain → 加灰云 A 记录 → 在 Worker 里加 Route `域名/*`」，否则 CF 会把解析锁死。本项目只负责维护 A 记录，不碰 Worker 绑定。

## 风险与边界

- **单点**：优选出来的 IP 是硬编码进 DNS 的，CF 调整路由后可能失效。定时任务会持续复扫并自动换掉失效的，但如果扫描间隔很长，中间这段时间就是坏的。建议间隔 ≤ 6 小时。
- **扫描本身有成本**：200 个候选 × 2 轮 = 400 次 TLS 握手，NAS 上大约 10~30 秒，流量很小（每次几百字节）。
- **不要拿它当"加速器"**：它解决的是"解析到坏 IP"，不是"提升带宽"。物理距离决定的延迟改不了。
- **API Token 存明文**在容器内 SQLite 里（`/data/app.db`）。这个文件等于你的 DNS 写权限，别把 `data` 目录丢到公开位置。

## 数据与备份

所有状态在 `/data/app.db`（一个 SQLite 文件）：管理密码哈希、CF Token、配置、扫描历史。备份复制这一个文件即可。

## 本地开发

```bash
pip install -r requirements.txt
DATA_DIR=./_testdata DB_PATH=./_testdata/app.db \
  python -m uvicorn app.main:app --reload --port 8080
```

## 目录结构

```
app/
  main.py        FastAPI 路由、会话认证、静态页面
  runner.py      扫描→决策→更新 主流程、定时循环、日志缓冲
  scanner.py     并发 IP 探测与优选排序
  cloudflare.py  Cloudflare API 客户端与记录同步
  store.py       SQLite 持久化
  static/
    index.html   管理页面（原生 JS，无构建）
```

## License

MIT
