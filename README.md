# Cloudflare 优选 IP 自动更新

自动扫描 Cloudflare 边缘 IP，挑出**在你这条宽带上真正连得通、而且快**的那几个，通过 Cloudflare API 写回 DNS 解析。带 Web 管理页面、定时任务，Docker 一条命令部署。

给的场景很具体：域名挂在 Cloudflare，源站（或 Worker）本身没问题，但解析到的 anycast IP 在本地被阻断 / 绕远路，表现为时快时慢、动不动几十秒超时。手动扫 IP、手动改 DNS 太麻烦，所以做成定时自动跑。

---

## 功能

- **扫描**：在 Cloudflare 官方网段内随机采样候选 IP，并发做 TLS 握手 + HTTP 首字节探测，记录机房代码（`colo`）、握手耗时、首字节耗时、成功率
- **优选**：按「成功率优先、延迟次之」排序，取前 N 个；成功率低于阈值或超时的直接淘汰
- **多域名**：一个 Cloudflare Token 下可以添加任意多个域名块，**每个块独立配置** Zone / 记录 / TTL / 代理 / 保留数量 / 探测覆盖 / 扫描间隔 / 切换阈值，互不影响
- **自动更新**：通过 Cloudflare API 把 DNS 记录同步成优选结果，只增删差异，不动其他记录
- **防误切**：新 IP 必须比现任快 `switch_margin_pct`% 才换；本轮没有达标 IP 时**保留现有解析不动**，避免把自己切死
- **定时任务**：每个域名块有自己的扫描间隔（默认 360 分钟，`0` 关闭），另有一个全局总开关可以一键暂停全部排期
- **Web 管理**：登录保护、块内实时状态（当前解析 / 上次结果 / 下次扫描 / 错误）、扫描结果表、运行日志
- **多值解析**：可同时保留 2~3 条 A 记录，CF 会轮询返回，天然互为备份
- **历史记录**：最近 300 次扫描结果落库（SQLite），带域名块归属，重启不丢

## 工作原理

```
          ┌─ 域名块 A（tgapi.example.com）
          ├─ 域名块 B（www.example.com）
          └─ 域名块 C（api.other.com）
                     │
每块按自己的间隔到点 ──> 采样候选 IP ──> 并发探测（TLS + HTTP 首字节）
                     │
                     ├─ 逐 IP 记录 colo / ttfb / 成功率
                     ▼
              排序 + 过滤（成功率、延迟阈值）
                     ▼
             取前 N 个 ──> 与「这一块」现有 DNS 记录比对
                              │
                              ├─ 现任都健康且新 IP 没快够 → 不动
                              └─ 需要更新 → 调用 CF API 增删记录
```

调度器每 5 秒醒一次，把所有「到点 + 已启用」的块排成队列依次执行；同一时刻只跑一个块，避免几百个并发 TLS 探测互相抢带宽把结果测歪。

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
      PUID: "1000"      # /data 的属主 UID，容器会 chown 成这个再降权运行
      PGID: "1000"      # 同上，GID
    restart: unless-stopped
```

```bash
mkdir -p /volume1/docker/cf-ip-optimizer && cd /volume1/docker/cf-ip-optimizer
# 把上面的 compose 存成 docker-compose.yml
docker compose up -d
```

打开 `http://NAS_IP:8787`，首次访问会让你设置管理密码（≥8 位）。

容器以 root 启动、把 `/data` 的属主改成 `PUID:PGID` 后立刻降权，再跑服务。所以宿主机上 `./data` 是 root 建的也没关系，**不用手动 chown**。想让数据文件的属主跟你账号一致，把 `PUID`/`PGID` 改成 `id -u` / `id -g` 的输出即可。

### 镜像地址

`ghcr.io/zlyon/cf-ip-optimizer`，`latest` 跟随 main 分支，也可以指定 `sha-xxxxxxx` 固定版本。amd64 / arm64 都构建了。

## 配置

配置分两层：

- **全局**：Cloudflare API Token、公共探测参数、调度默认值与总开关 —— 一份，所有块共用
- **域名块**：每个「域名 + 记录」一个块，独立的记录设置、探测覆盖、扫描间隔、自动更新开关

> 从旧版本升级：原来那套单域扁平配置（Zone / 记录名 / 间隔等）首次启动时会**自动迁移成一个域名块**，不用重新填。

### 1. 创建 Cloudflare API Token

Cloudflare 控制台 → 右上头像 → **My Profile → API Tokens → Create Token** → 用 **Custom token**：

| 权限 | 作用 |
|---|---|
| `Zone → DNS → Edit` | 读改 DNS 记录 |
| `Zone → Zone → Read` | 按名称查 Zone ID |

**Zone Resources** 选 `Include → Specific zone → 你的域名`，最小权限即可，不需要 Account 级权限。

只有一个 Zone 就选 Specific zone。要用多个 Zone，就选 `Include → All zones from an account`（或逐个加上那几个 Zone），Token 本身仍是一个，页面上的每个域名块填各自的 Zone 名称即可。

### 2. 全局设置（整站一份）

页面上的「全局设置」折叠块就是这一层，多个域名块共用。

| 字段 | 说明 |
|---|---|
| API Token | 上一步生成的 Token，所有域名块共用同一个；换 Token 只改这一处 |
| 探测路径 / 端口 | 块内没覆盖时用它 |
| 候选 IP 数量 / 采样轮数 / 并发 / 超时 / 成功率 / 延迟上限 | 公共探测参数，块内无需重复填 |
| 默认扫描间隔 / 默认切换阈值 | 新建域名块时的默认值，创建后各块独立 |
| 定时扫描总开关 | 关掉后所有块的排期清空，不再自动跑（手动扫描不受影响） |

### 3. 域名块（一个域一条记录一个块）

点「＋ 添加域名块」加一个块，右上角可以折叠，块头四个按钮：**扫描 / 测试 / 解析 / 删除**。

| 字段 | 说明 | 例子 |
|---|---|---|
| 备注名 | 只为好认，可留空 | `TG 反代` |
| Zone 名称 | 域名所在的 zone | `example.com` |
| 记录名 | 要维护的完整记录名 | `tgapi.example.com` |
| 记录类型 | `A` 或 `AAAA` | `A` |
| TTL | 1 表示自动 | `300` |
| 保留 IP 数量 | 同时保留几条记录 | `2` |
| 代理状态 | **Worker 场景必须关闭（灰云）** | 关 |
| 探测域名 | 留空用记录名，SNI / Host | 留空 |
| 探测路径 | 留空用全局 | 留空 |
| 扫描间隔 | 这个块自己的排期，`0` 表示不定时 | `360` |
| 切换阈值 | 新 IP 要比现任快多少 % 才换 | `15` |
| 自动更新解析 | 关掉后这个块只扫描；此时点「扫描」也不会写 DNS | 开 |
| 额外候选 IP / CIDR | 每行一个，会插在随机采样之前 | `104.16.0.1` |

块底部实时显示「当前解析 / 上次结果 / 下次扫描 / 错误」，出错会直接把 Cloudflare 返回的原话贴在块里（比如 Token 权限不足、同名 CNAME 挡路）。

同一 Zone 下不同记录不冲突；**同一 Zone + 同一记录名 + 同一类型**会被拒绝，避免两个块互相覆盖同一条记录。

填完先点块头的 **测试**，能看到当前记录就说明权限没问题。

## 使用建议

**第一次先"只扫描不更新"**，看结果表里有没有 `colo` 是 `HKG` / `NRT` / `SIN` 且延迟低的 IP。如果全是 `LAX`，说明这条宽带出口就是绕美西，优选 IP 能改善的是"避开被阻断的 IP"，改善不了物理距离。做法是先把块的「自动更新解析」关掉点「扫描」，或直接点工具栏的「全部只扫描」，确认结果没问题再打开。

**保留 2 条而不是 1 条**。CF 对同名多条 A 记录会轮询返回，一条挂了还有另一条；只有 1 条时，那个 IP 被阻断就等于整站不可达。

**TTL 设 300 秒左右**。太短会让 CF 调用频繁，太长切换后生效慢。

**Worker + 灰云的特殊约束**：如果你的域名是 Worker 的 Custom Domain，改优选的正确姿势是「删掉 Custom Domain → 加灰云 A 记录 → 在 Worker 里加 Route `域名/*`」，否则 CF 会把解析锁死。本项目只负责维护 A 记录，不碰 Worker 绑定。

**首次使用前必须删掉同名 CNAME**。Cloudflare 不允许同一主机名同时存在 CNAME 和 A 记录。如果你现在是「CNAME 指向某个优选域名」的做法，先把那条 CNAME 删掉，再让本工具接管——它会明确报错提示，不会静默失败：

```
「tgapi.example.com」当前是 CNAME 记录（指向 cdn.example.net）。
Cloudflare 不允许同名 CNAME 与 A/AAAA 记录并存，请先在 DNS 页面删除这条 CNAME
（并确认 Worker 的 Route 已配好）再运行。
```

## 风险与边界

- **单点**：优选出来的 IP 是硬编码进 DNS 的，CF 调整路由后可能失效。定时任务会持续复扫并自动换掉失效的，但如果扫描间隔很长，中间这段时间就是坏的。建议间隔 ≤ 6 小时。
- **扫描本身有成本**：200 个候选 × 2 轮 = 400 次 TLS 握手，NAS 上大约 10~30 秒，流量很小（每次几百字节）。
- **不要拿它当"加速器"**：它解决的是"解析到坏 IP"，不是"提升带宽"。物理距离决定的延迟改不了。
- **API Token 存明文**在容器内 SQLite 里（`/data/app.db`）。这个文件等于你的 DNS 写权限，别把 `data` 目录丢到公开位置。

## 常见问题

### 容器反复重启，日志里是 `sqlite3.OperationalError: unable to open database file`

数据目录写不进去。SQLite 只会回这一句，看不出是权限问题，实际原因通常是：

- 宿主机上的 `./data` 是 docker 自动建的，属主是 **root**、权限 0755，而容器里的进程是 **uid 1000**
- 或者这个路径被挂成了只读

现在镜像会在启动时自动 `chown` 并降权，正常不会再有这个问题。如果还是报错，日志会直接指出是哪个目录、什么权限、当前 uid 是多少，比如：

```
数据目录不可写：/data（drwxr-xr-x uid=0 gid=0（root:root））
当前进程 uid=1000。
宿主机上执行一次即可修复：sudo chown -R 1000:1000 <你挂载的 data 目录>
```

对应处理：`sudo chown -R 1000:1000 ./data`，或者把 `PUID`/`PGID` 设成该目录的属主。

### 首次使用报「同名 CNAME 与 A 记录并存」

Cloudflare 不允许同一主机名同时有 CNAME 和 A。先去 DNS 页面删掉那条 CNAME（Worker 场景还要确认 Route 已配好），再点扫描。工具会明确报错，不会静默跳过。

### 扫描结果全是 `LAX` 而且延迟很高

说明这条宽带的出口本来就在美西。优选 IP 只能避开被阻断的 IP，改不了物理距离。

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
  main.py        FastAPI 路由、会话认证、域名块 CRUD、静态页面
  runner.py      按块扫描→决策→更新 主流程、多块调度器、日志缓冲
  scanner.py     并发 IP 探测与优选排序
  cloudflare.py  Cloudflare API 客户端与记录同步
  store.py       SQLite 持久化（settings 全局 + targets 域名块 + scans 历史）
  static/
    index.html   管理页面（原生 JS，无构建）
docker-entrypoint.py  容器入口：修正挂载目录属主后降权到 PUID:PGID
tests/
  test_core.py   27 项单测：采样、colo 解析、记录同步、多块持久化、迁移、排期、启动报错
```

## License

MIT
