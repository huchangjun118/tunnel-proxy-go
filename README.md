# tunnel-proxy-go

一个**完全在进程内与本机回环之间运行**的转发代理与隧道接入实现，不依赖任何外部服务。
客户端通过**同一条接入地址**把到目标的连接封装成隧道，前端同时支持两种接入协议：

- HTTP `CONNECT`（请求行方式）
- SOCKS5（握手协商方式，含用户名/密码子协商 RFC 1929）

两种协议在**鉴权、目标解析、访问控制、并发限流、转发收尾**上共用同一条处理管线，
语义完全一致，任何一方都不会因为另一方的存在而出现行为偏差。

> 目标服务用本机回环（`127.0.0.1`/`localhost`）模拟，整条链路只有进程与 loopback。

---

## 1. 架构与处理管线

单个 TCP 监听器根据客户端的**第一个字节**做前端协议分发：

```
                 ┌──────────────── 单个监听地址 ────────────────┐
 client ──TCP──▶ │ Peek(1): 0x05 -> SOCKS5，否则按 HTTP CONNECT │
                 └──────────────────────────────────────────────┘
                                      │
        ┌─────────────── 两种前端共享同一管线 ───────────────┐
        │ 1. 握手/分帧   (handshake)  读取协商或请求行，限时   │
        │ 2. 凭据鉴权     (auth)       Basic / RFC1929         │
        │ 3. 目标规范化 + 访问控制 (acl)，先于任何拨号          │
        │ 4. 并发槽位     (limit)      拒绝(reject)或排队(queue)│
        │ 5. 解析 + 拨号  (dial)       DNS / 超时 / 拒绝 分类   │
        │ 6. 双向转发     (relay)      半关闭/空闲/总时长/异常  │
        └─────────────────────────────────────────────────────┘
```

关键不变量：

- **鉴权未通过、目标未放行、达到并发上限**时，一律在**建立到目标的连接之前**拒绝，
  代理绝不向目标发起拨号。
- 前端协议差异只体现在“如何读取凭据 / 目标 / 如何回写失败码”，决策逻辑是同一份代码。
- 所有失败都带 `阶段(stage) + 原因(reason)` 两级分类，可区分、可审计、可计数。

---

## 2. 协议语义

### 2.1 HTTP CONNECT

请求与应答：

```http
CONNECT 127.0.0.1:18080 HTTP/1.1
Host: 127.0.0.1:18080
Proxy-Authorization: Basic base64(user:pass)

HTTP/1.1 200 Connection Established
```

- 鉴权：`Proxy-Authorization: Basic ...`；缺失返回 `407`（带 `Proxy-Authenticate`），
  凭据错误返回 `403`。
- 非 CONNECT 方法返回 `405`；请求行/头部畸形返回 `400`。
- 首字节是控制字符（不可能是 HTTP 方法 token，例如 SOCKS4 的 `0x04`）时立即拒绝，
  不会挂起到握手超时。

### 2.2 SOCKS5（RFC 1928 / RFC 1929）

1. 方法协商：客户端 `05 NMETHODS METHODS...`，服务端选择
   `00`（免鉴权）或 `02`（用户名/密码）；要求鉴权但客户端只给免鉴权时回 `FF`。
2. 用户名/密码子协商：`01 ULEN USER PLEN PASS`，成功 `01 00`，失败 `01 01`。
3. CONNECT 请求支持 `ATYP=01`(IPv4)、`03`(域名)、`04`(IPv6)。
4. 失败按阶段映射为标准应答码：

| 管线原因 | SOCKS5 reply |
|---|---|
| 目标未放行 `target_denied` | `02` 不允许连接 |
| 目标非法 `target_invalid` | `01` 通用失败 |
| DNS 失败 `dns_failed` | `04` 主机不可达 |
| 拨号超时 `dial_timeout` | `06` TTL 超时 |
| 拨号失败 `dial_failed` | `05` 连接被拒绝 |
| 并发限制/排队超时 | `01` 通用失败 |

### 2.3 目标规范化（书写形式无关）

鉴权与 ACL 的判定不受地址/端口书写形式影响：

- IP 字面量经 `net.ParseIP` 归一化为数值比较：
  `127.0.0.1` 与 `[::ffff:127.0.0.1]` 视为同一目标；IPv6 统一压缩表示。
- 主机名转小写、去空白与方括号；禁止空格/控制字符、首尾点、连续点。
- 端口必须在 `1..65535`。
- 主机名的 DNS 解析**延迟到拨号阶段**，解析失败计入 `dial/dns_failed`，
  而不是在策略判定阶段误判。

---

## 3. 访问控制（ACL）

- `DefaultDeny=true` 时默认拒绝，必须显式 allow；否则默认放行、可显式 deny。
- 规则按**顺序首条匹配**生效。命令行将所有 `-deny` 规则排在 `-allow` 之前，
  因此命令行配置下“显式拒绝优先”。
- 规则可按：精确主机 / 域名后缀（`.example.com` 同时匹配 `example.com` 与子域）/
  CIDR（如 `10.0.0.0/8`）/ 端口 进行匹配；`Port=0` 表示任意端口。
- 子域名后缀不会误伤形似域名（`notexample.com` 不匹配 `.example.com`）。

---

## 4. 并发承载与资源上限

| 能力 | 说明 |
|---|---|
| `MaxTunnels` | 同时进行的隧道上限（信号量实现），`0` 视为 1 |
| `LimitPolicy=reject`（默认） | 满员立即拒绝：SOCKS 回 `01`，HTTP 回 `503` |
| `LimitPolicy=queue` | 满员排队，最多等待 `QueueTimeout`，超时回 `queue_timeout`。排队属于握手阶段，受 `HandshakeTimeout` 总时限约束，建议 `QueueTimeout <= HandshakeTimeout` |
| `DialTimeout` | 单次目标连接（含 DNS）的上限 |
| `HandshakeTimeout` | 整个前端握手（协商+鉴权+请求）的上限 |
| `IdleTimeout` | 单条隧道任一方向无数据传输的空闲上限，读超时即收尾 |
| `MaxLifetime` | 单条隧道存活总时长上限，到期强制收尾 |
| `HalfCloseTimeout` | 一端半关闭后，反向排空的最长等待，到期释放槽位 |
| `BufferSize` | 每方向拷贝缓冲 |

- 每个连接在**独立 goroutine** 中处理，拷贝使用独立缓冲与每方向读截止时间，
  任一连接的慢读慢写只会让其自身在截止时间到期后收尾，**不会阻塞其它连接**。
- 排队等待与服务器关闭联动：`Close()` 会取消排队，等待者立即得到 `queue_timeout`。

---

## 5. 双向转发的正确收尾

- **半关闭**：一端读到 EOF（FIN）时，对另一端调用 `CloseWrite()` 传播半关闭，
  反方向继续转发直到也结束（真正的 TCP 半关闭，而不是立即全关）。
- **半关闭排空**：半关闭后若对端长时间不结束，`HalfCloseTimeout` 到期强制全关，
  避免对端“只收不发不关”导致槽位长期驻留。
- **异常断开 / RST**：任一方向发生非良性错误（reset、写失败等）立即强制关闭两端，
  唤醒另一方向阻塞读；被强制唤醒产生的 `ErrClosed` / `EPIPE` / `ECONNRESET`
  属于正常收尾，**不计为 relay 错误**。
- **服务器关闭**：同时强制关闭前端连接与已建立的目标连接，并等待所有处理 goroutine
  退出，杜绝连接泄漏、重复关闭和中间状态残留；`Close()` 可重复调用。

---

## 6. 可观测性

`Server.Metrics()` 返回一致性快照（`MetricsSnapshot`，原子计数）：

- `ActiveTunnels` 当前隧道数、`TotalTunnels` 累计隧道数
- `BytesUp`（client→target）、`BytesDown`（target→client）累计字节
- `Rejected[Reason]` 各类**拒绝**计数
- `Errors[Stage]` 各**阶段**错误计数

还可通过 `Server.SetAuditHook(func(AuditEvent))` 接收每个会话结局
（阶段、原因、明细、是否接受、身份、目标），用于审计。

### 错误分类

- 阶段 `stage`：`handshake | auth | acl | limit | dial | relay`
- 原因 `reason`：`protocol_error, unsupported_protocol, auth_required, auth_failed,
  target_invalid, target_denied, limit_rejected, queue_timeout, dns_failed,
  dial_timeout, dial_failed, idle_timeout, lifetime_expired, relay_broken`

**建隧道前**的拒绝（鉴权/ACL/限流/握手类）计入 `Rejected`；任何分类失败都计入对应
`Errors[stage]`。目标解析失败、连接超时、转发中途断网分别落在 `dns_failed /
dial_timeout / dial_failed / relay_broken|idle_timeout`，失败以**协议失败码**返回，
绝不会被当作正常隧道数据回传给客户端。

---

## 7. 配置项（命令行）

```bash
go run ./cmd/tunnel-proxy \
  -listen 127.0.0.1:1080 \          # 两种协议共用的接入地址
  -user alice -pass s3cret \        # 启用凭据鉴权（不设 user 则免鉴权）
  -default-deny \                   # 默认拒绝目标
  -allow 127.0.0.1:18080 \          # 放行规则，可重复；支持 host[:port]/.domain/CIDR[:port]
  -deny 127.0.0.1:9999 \            # 拒绝规则（排在 allow 之前，显式拒绝优先）
  -max-tunnels 64 \                 # 并发隧道上限
  -queue \                          # 满员排队（默认立即拒绝）
  -queue-timeout 5s \
  -dial-timeout 5s -handshake-timeout 10s \
  -idle-timeout 2m -max-lifetime 10m -half-close-timeout 5s \
  -metrics-period 5s
```

默认监听 `127.0.0.1:1080`，默认免鉴权、默认放行目标（便于本地实验；生产请开启
`-default-deny` 与显式 `-allow`）。

---

## 8. 本地验证

### 8.1 自动化测试

```bash
go test ./...            # 全量测试
go test -race ./...      # 竞态检测
go test -run TestLimit ./...
```

覆盖：

- 两种接入方式正向转发与字节计数一致性（`TestProtocolParity`）
- 鉴权失败（缺凭据/错密码，SOCKS 与 HTTP）、鉴权成功
- ACL 拒绝、IP/IPv4-mapped-IPv6/端口书写形式无关性、域名后缀、CIDR
- 并发上限立即拒绝、排队成功与排队超时、且拒绝不会拨号到目标
- 半关闭、对端 RST、客户端异常断开、空闲超时、总寿命到期、服务器关闭
- 目标解析失败 / 连接拒绝的阶段区分
- 高并发频繁建连断连下的指标一致性与无泄漏（`TestMetrics_Churn`、`TestMetrics_ConcurrentRejects`）
- 畸形协议、非 CONNECT 方法、SOCKS5 方法协商等边界

### 8.2 手工端到端（loopback）

一个终端起回环目标，另一个起代理，然后用 curl：

```bash
# 目标（任选其一）
python3 -m http.server 18080 --bind 127.0.0.1

# 代理
go run ./cmd/tunnel-proxy -listen 127.0.0.1:11080 \
  -user alice -pass s3cret -default-deny -allow 127.0.0.1:18080

# HTTP CONNECT
curl -p --proxy alice:s3cret@127.0.0.1:11080 http://127.0.0.1:18080/

# SOCKS5（同一端口）
curl --socks5 alice:s3cret@127.0.0.1:11080 http://127.0.0.1:18080/
```

---

## 9. 主要源码

| 文件 | 职责 |
|---|---|
| `config.go` | 配置项、目标规范化 `parseTarget` |
| `errors.go` | 阶段/原因分类、`ProxyError` |
| `auth.go` | 凭据鉴权（常量时间比较） |
| `acl.go` | 访问控制规则求值 |
| `metrics.go` | 原子指标与快照 |
| `tunnel.go` | 并发槽位管理、双向转发与收尾 |
| `server.go` | 监听器、首字节分发、共享管线 `openTarget`、生命周期 |
| `socks.go` | SOCKS5 协商/鉴权/CONNECT/应答码映射 |
| `httpconnect.go` | HTTP CONNECT 请求解析/鉴权/状态码 |
| `cmd/tunnel-proxy/main.go` | 命令行入口 |
