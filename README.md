# ruijie-sslvpn-socks5（rj-socks）

根据 `RG-SSLVPN_2.5.0_Build20260917_Setup.exe` 中的原生协议实现的 Go 命令行客户端 `rj-socks`：登录锐捷 SSLVPN，建立 DTLS 数据通道，再提供本地 SOCKS5 TCP 代理。

程序使用用户态 IPv4 网络栈，不安装虚拟网卡、不修改系统路由。SOCKS5 的连接和域名解析均经 VPN；不会在隧道失败时改为本机直连。安装包只用于分析，不随本仓库分发；运行不依赖其中的 EXE、DLL 或驱动。

**实机验证：**已通过当前网关的账号登录、DTLS 1.2 握手、地址下发和 SOCKS5 收发验证；通过代理连接用户指定的内网 SSH 服务并收到其握手标识。当前网关没有下发 DNS，访问内网 IP 可用。其他网关及额外认证方式尚未实测；证据与支持边界见 [analysis/PROTOCOL.md](analysis/PROTOCOL.md)。

## 安装

### Scoop（Windows）

```powershell
scoop bucket add nemo https://github.com/xiongnemo/windows-binaries-scoop-bucket
scoop install nemo/rj-socks          # 正式版
scoop install nemo/rj-socks-nightly  # 跟踪 dev 分支的 prerelease
```

### Linux 软件包与 MacPorts

Linux 构建（`386`、`amd64`、`armv7`、`arm64`、`loong64`、`ppc64le`、`riscv64`、`s390x`）同时打成 `.deb`、`.rpm` 和 `.apk`，随每个 release 发布，也可以从 [package.anzupop.com](https://package.anzupop.com) 安装（那里也有 dnf、apk 和 MacPorts 的用法）：

```bash
sudo curl -fsSLo /usr/share/keyrings/nemo.gpg https://package.anzupop.com/keys/nemo-packages.gpg
echo "deb [signed-by=/usr/share/keyrings/nemo.gpg] https://package.anzupop.com/apt stable main" | sudo tee /etc/apt/sources.list.d/nemo.list
sudo apt update && sudo apt install rj-socks
```

示例配置装在 `/usr/share/rj-socks/config.yaml.example`。把 `stable` 换成 `nightly` 即跟踪 dev 构建。

### 预编译二进制

每个 [release](https://github.com/xiongnemo/ruijie-sslvpn-socks5/releases) 都有 Windows、macOS 和 Linux（含 mips、ppc64 等）的压缩包，内含 `rj-socks`、`config.yaml.example`、本说明和第三方许可声明。

### 版本

推送精确的 `vX.Y.Z` tag 发布正式版，`rj-socks -version` 输出的就是这个干净的版本号。之后每次推送 dev 发布 prerelease `vX.Y.N-dev-<提交>`，N 为 tag 的 patch 加上 tag 之后的提交数；它的软件包版本是该版本的预发布（`1.0.3~pre-1`，apk 为 `1.0.3_pre-r1`）。每个包在发布前都会在 Debian、Ubuntu、Fedora、Rocky Linux 和 Alpine 上实际安装并运行。

## 使用

```powershell
Copy-Item config.yaml.example config.yaml
# 编辑 config.yaml：vpn.server、vpn.username、vpn.password
rj-socks -config config.yaml
```

已经填写过 `config.yaml` 时直接运行，勿用示例覆盖。`-config` 默认为当前目录的 `config.yaml`。

仅在收到网关配置并建立用户态网络栈后才开始监听 SOCKS5。默认地址是 `127.0.0.1:1080`，按 Ctrl+C 关闭连接并退出。可用以下命令验证代理（换成你有权限访问的内网 URL）：

```powershell
curl.exe --socks5-hostname 127.0.0.1:1080 http://intranet.example/
```

`--socks5-hostname` 把域名交给 VPN DNS 解析。若网关未下发 DNS，IP 地址仍可使用，域名请求会明确失败。

### 从源码运行

需要 Go 1.27.2 或更新版本。首次下载依赖需要访问 Go 模块代理。

```powershell
go run ./cmd/rj-socks -config config.yaml
# 或者先编译
go build -o bin/rj-socks.exe ./cmd/rj-socks
.\bin\rj-socks.exe -config config.yaml
```

## 证书信任

启动先检查网关证书，再发送认证信息。正常受信任证书直接使用；遇到有效的自签名证书时，终端显示网关地址、证书主体、有效期、SHA-256 指纹，以及名称是否匹配，并提供：

1. **不信任**：终止连接；回车默认选此项。
2. **信任一次**：只在当前进程内信任该网关的这张证书，不改配置。
3. **一直信任**：在确认握手成功后，把证书指纹写到当前配置文件的 `vpn.tls.trusted_certificates`，保留其他配置和注释。

保存的信任绑定到 `https://主机:端口` 和具体证书。自签名证书变更会重新询问；运行中的连接遇到未知证书会失败，下次启动再确认。过期、无效签名等证书不能通过上述选择绕过。也可通过 `ca_file` 指定 PEM 格式 CA，相对路径以配置文件所在目录为准。程序不接受 `insecure_skip_verify: true`。

信任选项只从终端读取，非交互运行时应预先配置可信 CA 或已经确认的指纹。配置含密码，请妥善保存；项目忽略 `config.yaml`。可用 `password_env` 引用环境变量名，同时把 `password` 留空。

## 诊断与测试

```powershell
# 打印版本
rj-socks -version
# 只校验配置，无网络请求
rj-socks -check-config
# 只完成证书检查，不发送用户名密码
rj-socks -probe certificate
# 登录并检查下发的隧道参数，然后退出并注销
rj-socks -probe login

go test ./...
go test -race ./...
go vet ./...
```

日志不打印密码、HTTP 会话 Cookie 或隧道密钥。`-probe login` 只显示隧道端点、版本和压缩模式。

兼容已验证网关下发的 IP/端口前后空白。少量认证 HTTP 请求使用独立连接，避免网关多余的 gzip/chunk 数据进入空闲连接池。数据隧道保持长连接。

## 当前支持范围

- 账号密码登录：旧版 form、`loginSec`、`loginv2`，按服务端能力 Cookie 选择；失败不自动降级重试。
- DTLS 1.2 和锐捷的 HMAC-SHA1 Cookie 认证；包含实测网关所需的 `ECDHE-RSA-AES256-SHA384` 套件，复用 Pion 的 CBC/PRF 实现；LZO1X 数据报压缩/解压。
- 隧道会话、配置 TLV、控制 ACK/重传、保活、IPv4 TCP 与 VPN DNS。
- SOCKS5 CONNECT、可选用户名密码认证、超时、连接数限制和退出清理。

尚未完成 DTLS 1.0、短信/OTP/客户端证书等额外认证流程、IPv6 VPN 和 SOCKS5 UDP ASSOCIATE/BIND。这些情况明确失败，不会退回本机直连。不会实现原客户端的界面、自动更新或全局路由接管。
