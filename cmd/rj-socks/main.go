package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/xiongnemo/ruijie-sslvpn-socks5/internal/config"
	"github.com/xiongnemo/ruijie-sslvpn-socks5/internal/trust"
	"github.com/xiongnemo/ruijie-sslvpn-socks5/internal/version"
	"github.com/xiongnemo/ruijie-sslvpn-socks5/internal/vpnauth"
)

func main() {
	if err := run(); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "错误:", err)
		os.Exit(1)
	}
}

func run() error {
	path := flag.String("config", "config.yaml", "YAML configuration file")
	probe := flag.String("probe", "", "diagnose certificate or login without starting SOCKS5")
	check := flag.Bool("check-config", false, "validate configuration without connecting")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version.Version)
		return nil
	}
	c, err := config.Load(*path)
	if err != nil {
		return err
	}
	if *check {
		fmt.Println("配置有效。")
		return nil
	}
	if *probe != "" && *probe != "certificate" && *probe != "login" {
		return errors.New("probe must be certificate or login")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	base, err := c.VPN.TLS.Build()
	if err != nil {
		return err
	}
	fmt.Println("检查 VPN 网关证书…")
	tc, err := trust.Build(ctx, c.VPN.Server, base, c.VPN.TLS.TrustedCertificates, func(info trust.CertificateInfo) (trust.Decision, error) { return promptTrust(ctx, info) }, func(origin, fingerprint string) error { return config.SaveTrust(*path, origin, fingerprint) })
	if err != nil {
		return err
	}
	fmt.Println("网关证书检查通过。")
	if *probe == "certificate" {
		return nil
	}
	client, err := vpnauth.New(vpnauth.Options{Server: c.VPN.Server, Username: c.VPN.Username, Password: c.VPN.Password, HardwareID: c.VPN.HardwareID, TLSConfig: tc, Timeout: c.Timeouts.Connect})
	if err != nil {
		return err
	}
	defer client.Close()
	fmt.Println("登录 VPN…")
	session, err := client.Login(ctx)
	if err != nil {
		return err
	}
	defer func() {
		logoutCtx, closeLogout := context.WithTimeout(context.Background(), 5*time.Second)
		defer closeLogout()
		if err := client.Logout(logoutCtx); err != nil {
			fmt.Fprintln(os.Stderr, "注销 VPN 失败:", err)
		}
	}()
	fmt.Printf("登录成功，收到 %d 字节隧道参数。\n", len(session.TunnelParameters))
	if *probe == "login" {
		return printTunnelSummary(session)
	}
	return serveVPN(ctx, c, tc, session)
}

func promptTrust(ctx context.Context, info trust.CertificateInfo) (trust.Decision, error) {
	fmt.Fprintf(os.Stderr, "\nVPN 网关使用未知自签名证书。\n网关: %s\n主体: %q\n签发者: %q\n有效期: %s — %s\nSHA-256: %s\n", info.Origin, info.Subject, info.Issuer, info.NotBefore.Format(time.RFC3339), info.NotAfter.Format(time.RFC3339), info.SHA256)
	if info.HostnameMismatch {
		fmt.Fprintln(os.Stderr, "证书名称与网关地址不匹配；信任将绑定到上述网关和证书指纹。")
	}
	fmt.Fprintln(os.Stderr, "[1] 不信任  [2] 信任一次  [3] 一直信任（写回配置）")
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Fprint(os.Stderr, "请选择 [1/2/3，默认 1]: ")
		type answer struct {
			line string
			err  error
		}
		result := make(chan answer, 1)
		go func() { line, err := reader.ReadString('\n'); result <- answer{line, err} }()
		var line string
		var err error
		select {
		case <-ctx.Done():
			return trust.Reject, ctx.Err()
		case a := <-result:
			line, err = a.line, a.err
		}
		if err != nil {
			return trust.Reject, errors.New("无法读取证书信任选择；请在交互终端运行")
		}
		switch strings.TrimSpace(line) {
		case "", "1":
			return trust.Reject, nil
		case "2":
			return trust.TrustOnce, nil
		case "3":
			return trust.TrustAlways, nil
		default:
			fmt.Fprintln(os.Stderr, "请输入 1、2 或 3。")
		}
	}
}
