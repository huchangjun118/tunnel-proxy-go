# tproxy — 本地转发代理与隧道接入（CONNECT + SOCKS5）

一个只在**进程内与本机回环**之间运行的转发代理。客户端通过**同一条接入地址**，
用两种接入协议之一把到目标的连接封装成隧道转发：

- **HTTP CONNECT**：请求行 `CONNECT host:port`，`Proxy-Authorization: Basic` 鉴权；
- **SOCKS5**（RFC 1928 + RFC 1929）：握手协商，`0x02` 用户名/密码鉴权，
  支持 IPv4 / 域名 / IPv6 目标。

两种方式在**鉴权、目标解析、访问控制、连接建立**上走同一条内部流水线，语义完全一致。
目标由本机回环服务模拟，不依赖任何外部服务。

## 能力总览

| 需求 | 实现 |
| --- | --- |
| CONNECT / SOCKS5 同址并存 | 首字节嗅探（`0x05` → SOCKS5，可见 ASCII → CONNECT），共享 `proxy.Engine` |
| 凭据鉴权 | Basic / RFC1929，恒定时间比较；缺失与错误凭据返回可区分结果（407 / 0x01） |
| 目标访问控制 | 规范化后匹配主机/端口；拒绝发生在拨号**之前**，绝不建立目标连接 |
| 书写形式无关 | `localhost`/`127.0.0.1`/`::1`/`127.1`/IPv6 压缩/域名尾点统一归一化 |
| 并发上限 | 信号量限并发；超限策略 `reject`（立即 503/0x06）或 `queue`（排队至超时） |
| 慢对端隔离 | 每条隧道独立读截止时间；一个慢连接不阻塞其他连接 |
| 空闲/总时长 | `idle-timeout`（无数据即回收）、`total-timeout`（隧道最大寿命） |
| 双向收尾 | EOF 半关闭（FIN）端到端传播；半关闭后短 drain 窗口继续放行响应数据；异常/超时立即收尾 |
| 防泄漏 | `sync.Once` 保证连接恰好关闭一次；defer 链释放槽位/取消上下文/关闭上游 |
| 可观测 | JSON 指标端点：在途隧道、累计字节、拒绝分类、错误分阶段计数 |
| 异常可解释 | 错误带阶段（protocol/auth/acl/resolve/dial/limit/queue/io）与原因；失败帧不与隧道数据混淆 |

## 目录结构

```
config/   配置项与校验
target/   目标地址规范化（鉴权/ACL/拨号统一依据）
auth/     凭据鉴权（恒定时间）
acl/      主机/端口访问控制
metrics/  并发安全计数与快照
pool/     并发上限（reject/queue）
proxy/    共享引擎 + CONNECT/SOCKS5 前端 + 双向转发与收尾
server/   同址监听、协议嗅探、生命周期、metrics HTTP
cmd/tproxy/ 可执行入口
e2e/      端到端自动化测试
testutil/ 回环目标服务与测试客户端
```

## 协议语义

### 共同流水线（CONNECT 与 SOCKS5 完全一致）

1. **解析**：CONNECT 从请求行 authority 取目标，SOCKS5 从 `DST.ADDR/DST.PORT` 取；
   两者都交给 `target.Parse` 归一化。
2. **鉴权**：同一 `auth.Authenticator.Check`。
   - CONNECT 失败 → `407 Proxy Authentication Required`（带 `Proxy-Authenticate: Basic`）。
   - SOCKS5 无可用方法 → 方法选择 `0xFF`；用户名/密码错误 → 子协商状态 `0x01`。
3. **ACL**：对**归一化目标**判主机与端口。拒绝 → CONNECT `403`，SOCKS5 `0x02`。
   此步在任何网络拨号之前。
4. **并发准入**：占用池槽位；满则按 `reject`/`queue` 处理。
   - CONNECT：`503`（满）或 `504`（排队超时）。
   - SOCKS5：`0x06`（TTL/资源类失败）。
5. **拨号**：受 `dial-timeout` 约束。
   - 解析失败 → 阶段 `resolve`，CONNECT `502`，SOCKS5 `0x04`。
   - 拒绝连接 → `dial/connection_refused`，SOCKS5 `0x05`；不可达 → `0x03`。
6. **成功帧**：仅在目标连接建立后发送（CONNECT `200 Connection Established`、
   SOCKS5 reply `0x00`），随后进入隧道。因此**失败结果永远不会被当成隧道数据**。
7. **双向转发与收尾**：见下。

### 半关闭与收尾

- 任一方向读到干净 EOF → 对其写侧调用 `CloseWrite`（TCP FIN），对端据此感知半关闭；
- 半关闭后，仍开启的反方向进入一个**短 drain 窗口**（默认 500ms），期间在途响应数据
  继续转发并刷新窗口——支持“客户端发完请求即半关闭、服务端继续流式回包”；
- 空闲截止时间随每次成功读取刷新；总寿命到期立即关闭双侧；
- RST/读写异常立即终止整条隧道；`sync.Once` + defer 保证不重复关闭、不泄漏槽位与 fd。

### 地址规范化

`target.Parse` 不做 DNS，仅规范化文本：

- `localhost`、`ip6-localhost`、`::1`、所有 `127.0.0.0/8` 回环地址 → `127.0.0.1`；
- IPv4 简写（`127.1`、整数形式等 inet_aton 写法）、IPv4-mapped IPv6 → 标准点分；
- IPv6 → 标准压缩形式；域名转小写、去尾点。

所以 ACL 规则 `localhost` 同时匹配 `127.0.0.1`、`::1`、`127.1` 等所有写法。

## 配置项（命令行参数）

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-listen` | `127.0.0.1:18080` | CONNECT + SOCKS5 共用接入地址 |
| `-metrics` | `127.0.0.1:18081` | JSON 指标地址（`/metrics`、`/stats`），留空关闭 |
| `-user` | 空 | `user:pass`，多个用逗号分隔；设置即开启鉴权 |
| `-allow-hosts` | 空=全部 | 允许的主机/IP/后缀（`.example.com` 匹配域及子域），逗号分隔 |
| `-allow-ports` | 空=全部 | 允许的 TCP 端口，逗号分隔 |
| `-max-tunnels` | `1024` | 最大并发隧道数，`<=0` 不限 |
| `-overflow` | `reject` | 达上限策略：`reject` 或 `queue` |
| `-queue-timeout` | `5s` | queue 策略下最长排队时间 |
| `-idle-timeout` | `2m` | 单隧道无数据空闲回收时间 |
| `-total-timeout` | `10m` | 单隧道最大存活时间 |
| `-dial-timeout` | `5s` | 目标连接（含解析）超时 |
| `-buf-kb` | `32` | 每方向转发缓冲区（KiB） |

### 指标字段

```json
{
  "active_tunnels": 0,          // 当前在途隧道
  "total_tunnels": 12,          // 累计建立隧道
  "bytes_client_to_target": 340,// 累计上行字节
  "bytes_target_to_client": 340,// 累计下行字节
  "rejected_auth": 1,           // 鉴权拒绝
  "rejected_acl": 0,            // ACL 拒绝
  "rejected_limit": 0,          // 达上限立即拒绝
  "rejected_queue": 0,          // 排队超时/取消
  "errors_resolve": 0,          // 解析阶段错误
  "errors_dial": 0,             // 拨号阶段错误
  "errors_io": 0,               // 转发异常（空闲/总时长回收不计入）
  "errors_protocol": 0          // 协议帧错误
}
```

审计日志（stdout，标准 logger）逐条记录 accept/reject/failure，含
`remote`、`user`、`target`、`stage`、`cause`，拒绝结果可区分可追溯。

## 本地运行

```bash
go build -o tproxy ./cmd/tproxy

./tproxy \
  -listen 127.0.0.1:18080 \
  -user alice:secret \
  -allow-ports 9000 \
  -max-tunnels 64 \
  -overflow queue -queue-timeout 2s \
  -idle-timeout 30s -total-timeout 5m
```

用 curl 经 CONNECT 访问本机回环目标（目标自行监听在 127.0.0.1:9000）：

```bash
curl -p --proxy http://alice:secret@127.0.0.1:18080 http://127.0.0.1:9000/
```

SOCKS5：

```bash
curl --socks5 127.0.0.1:18080 --socks5-hostname 127.0.0.1:9000 http://127.0.0.1:9000/ # 无鉴权
# 带用户名/密码可用支持 SOCKS5 子协商的客户端（测试见 e2e）
```

## 验证方法

全部自动化，无需外部服务：

```bash
go test ./...            # 单元测试
go test -race ./...      # 竞态检测
go test -race -count=10 ./e2e   # 端到端稳定性重复
```

端到端覆盖（`e2e/`，目标全部为本机回环模拟）：

- 两种协议的正常双向转发与字节计数等价性；
- 缺失/错误凭据（407、SOCKS5 `0xFF`/`0x01`），且被拒请求**不触达目标**；
- 主机/端口 ACL 拒绝（403 / `0x02`），拒绝前不拨号；
- `localhost`/`127.1`/`::1` 等不同写法命中同一条 ACL；
- 并发上限立即拒绝、排队超时、排队后在槽位释放时准入；
- 慢对端不阻塞其他隧道；
- 端到端半关闭（FIN 传播 + 半关闭后响应数据仍到达）；
- 目标 RST、客户端静默离开、空闲超时、总时长超时的资源回收；
- 连接拒绝、解析失败的分阶段错误码（CONNECT/SOCKS5 各自映射）；
- 握手与首批隧道数据同包（粘包）不丢数据；
- metrics JSON 端点计数一致、频繁建断后 `active_tunnels` 归零。
