# RG-SSLVPN 2.5.0 协议证据与实现进度

## 目标与证据身份

- 安装包 SHA-256：`ad605fadbd0069d072ff7f1ab322771ccd2060832f2abde56ff10ee1c9cf164d`。
- 原生插件 `iptunctrl_plugin.dll` SHA-256：`51d9753ff1077996c4ab4382a921c1242f53fb9aba4a8202eff1f3536644316c`，AMD64。
- REA 安装包静态库存：`rea-installer.json`，父 Evidence `ev_047b18638e9941b202e3f2638d01afee5a8267ad6e9c9607376e03bab9f38553`。其库存只覆盖根 PE，不覆盖 Inno 内容。
- REA 插件导出表：`rea-plugin-exports.json`，Evidence `ev_daa9b768737d1046b8285cb74d69215b2dc4fa379b54c8180a8baf5612a62eaa`。
- 通过已安装的 innounp 2.71.2 解包 Inno Setup 6.3.0；未运行安装器。解包文件身份在 `artifact-hashes.json`。
- REA MCP 未配置 Ghidra，现有本机 Ghidra 12.2 被直接调用执行静态分析。`scripts/ghidra/ExportProtocol.java` 生成字符串引用与定点伪代码。以下地址均属于上述插件，不能把这些静态结果称为运行时观察。

## 认证

| 事实 | 静态来源 | 实现 |
| --- | --- | --- |
| 初始 origin GET 与能力 Cookie，`c_funcset1=127` | `1800839f0`、`1800ad680` | `internal/vpnauth` |
| `s_funcset1` bit 1 选择 JSON loginv2，bit 0x10 选择加密 form loginSec，其余 legacy login | `18008d3c0` | 按服务端声明选择，不在登录失败后降级 |
| AES-128-CBC，PKCS7，随机 16 字节密钥前缀，IV 为 `sslvpnauthr5` 后补零，整体 Base64 | `180082cd0`、`18013eba0`、`18013faf0` | 使用 Go crypto；crypto/rand 替代原客户端 rand |
| loginv2 `pwd` 加密密码，`passwd2` 加密含 uname/passwd/sid 的 JSON | `18008d3c0` | 独立 OpenSSL 向量与 TLS mock 测试 |
| 成功 JSON code=0，data.iptunParam 是 Base64 二进制 TLV；旧版 HTML 成功后请求 getIPAccessParam | `180097a80`、`18007df20`、`1800854b0` | 有界解析、保留同源 Cookie |

## 隧道

`iptunParam` 使用 `type:u8,length:BE16,value`。`1800ca6e0` 解析 type1=IP、2=UDP 端口、3=会话 ID、4=超时、5=LZO、6=16 字节 secret、7=DTLS 版本文本。包含 `dtls1.2` 时原客户端允许 DTLS 1.2，否则仅使用 DTLS 1.0。

实机返回的 type1 为带尾部空格的 IP，type2 为带前导空格的端口。文本字段现在先移除首尾空白再解析；32字节会话 ID 和16字节 secret 始终按原字节保留。回归测试同时覆盖带空白的文本和首尾恰好为空格字节的二进制凭据。

DTLS 自定义 Cookie 的完整证据见 [dtls-implementation.md](dtls-implementation.md)。当前 Go 实现使用 Pion DTLS 1.2，通过 ClientHello hook 对 20 字节 HelloVerifyRequest Cookie 应用 `HMAC-SHA1(secret16,cookie20)`。其余长度不改变。该规则已通过原始 UDP 握手报文字节测试；加密读写另由真实本地 DTLS 服务验证。

DTLS application datagram 以一个类型字节开始（`180068540`、`180074340`、`180075a50`）：1=IPv4，2=控制，4/20=心跳，8=退出。LZO 模式对整个 application datagram 压缩（`1800b6de0`）。

控制头 8 字节：版本1、flags（0=data/1=ACK）、BE16 payload length、BE16 sequence、BE16 ack。payload TLV 使用 `type:u8,length:u8,value`。客户端先发送 type1=32字节会话 ID，收到 ACK 后发送 type2=空的配置请求（`1800e1e50`）。服务器配置包括 `0x81`=虚拟 IPv4/掩码、`0x82`=DNS、`0x8d`=配置结束（`180069370`、`180078180`）。实现包含 ACK、重复报文处理、控制重传、有界队列和保活。

定点复核 `180068e70` 与 `180074ff0` 确认：发送序号复位为0，每次新控制消息在实际发送前加1，故首发序号为1；服务器首收期望同样为1。心跳的两个 BE16 字段是 hold timeout 与 send interval，默认180秒与30秒；接收心跳的期限是 hold+10秒，不是两个字段相乘（`180072300`）。测试固定这些源自安装包的常数，避免只让客户端与模拟网关的同一错误互相通过。

扩展心跳由 `s_funcset1 & 0x08` 协商，和 DTLS 1.2 文本、LZO 开关分别独立。汇编 `180083f7d` 至 `180083f81` 检查能力位，`180086004` 至 `18008601a` 将其作为第六参数传给 `1800cb2b0`；经 `1800cbc60` 和 `18006df00` 进入协议状态。已实现39字节扩展报文、所有应用帧的收发计数、首次立即保活，以及心跳过期时对实际收包活动的检查。发送和接收计数字段的具体位置见 [tunnel-wire-review.md](tunnel-wire-review.md)；压缩与非压缩的独立网关测试固定这些位置。

用户态网络栈是实现设计选择，不是原客户端行为。原客户端把 IPv4 写到虚拟网卡，本实现把它交给 gVisor，并将 SOCKS5 TCP/DNS 全部送入这条链路。

## 完成审核

| 用户要求/必要环节 | 当前证据 | 状态 |
| --- | --- | --- |
| 使用 reverse-engineer-anything skill | REA 库存/导出 Evidence、绑定哈希、静态源码位置 | 已完成静态取证 |
| Go 项目与 YAML 示例 | go.mod、cmd、internal、config.yaml.example | 已实现 |
| 启动自签名证书三选项与写回配置 | internal/trust、config.SaveTrust，真实 TLS 单测；用户选择3后的重启 | 已实现；已保存的同一证书在实机重启时直接通过 |
| 登录协议 | 静态调用链、独立加密向量、TLS mock；当前网关真实账号登录 | 已验证登录并收到104字节隧道参数 |
| 真实 VPN 协商/收发 | DTLS1.2/c028握手、控制ACK、配置下发与真实代理流量 | 实机通过；LZO实机未启用，压缩模式由独立向量/离线测试覆盖 |
| 连接后提供可用 SOCKS5 | 最终EXE监听127.0.0.1:1080；SOCKS5 CONNECT和内网SSH握手标识 | 实机通过 |

## 2026-11-09 实机结果

- 用户明确选择“一直信任”并写回配置；后续Go程序及最终EXE重启均未再次询问同一证书。
- 修复文本TLV空白后，确认网关宣告 `dtls1.0;dtls1.2`、无LZO、启用扩展心跳。
- 独立OpenSSL4.1对照（MTU1472）成功协商DTLS1.2、`ECDHE-RSA-AES256-SHA384`，证书校验通过。Go通过Pion公开扩展接口补充0xc028，随后握手成功。
- 网关分配了虚拟IPv4，未下发DNS；SOCKS5监听 `127.0.0.1:1080`。
- 经SOCKS5连接网关HTTP服务收到302；外部 `1.1.1.1:443` 在8秒内未连通，因此不声称VPN提供公网出口。
- 用户指定的内网SSH服务：通过SOCKS5发送SSH客户端标识并收到服务端的SSH标识；使用移除临时诊断后重新编译的最终EXE重复验证成功。未进行SSH账号认证。
- 最终EXE SHA-256：`26dc88eb3fdf3256b251f7f27ee5b4f424ff5d4244817563933f9da9a56762cf`；该文件已再次执行上述实机测试。最终代码通过 `go test -race ./...`、`go vet ./...`、构建和配置校验。
- 初始HTTP控制响应后多余的gzip/chunk字节已实机复现。为认证/注销请求关闭连接复用后，实机登录不再出现idle-channel警告；原始TLS报文正反对照测试覆盖这一策略。未屏蔽全局日志。
- 原生 `18008e4b0` 在logout URL后追加 `?arg=` 与七位随机数，Go注销请求已补上同样查询参数。

该结果证明当前网关下的“启动、登录、连接VPN、提供SOCKS5 TCP代理”链路。没有把它扩展为所有网关兼容性声明：DTLS1.0、额外认证和IPv6仍未实现；当前网关未提供DNS，域名解析未在该网关实测。凭据、Cookie、会话ID、secret和临时明文抓包均未写入本报告。
