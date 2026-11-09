package main

import (
	"fmt"
	"github.com/xiongnemo/ruijie-sslvpn-socks5/internal/tunnel"
	"github.com/xiongnemo/ruijie-sslvpn-socks5/internal/vpnauth"
)

func printTunnelSummary(s *vpnauth.Session) error {
	p, err := tunnel.ParseParameters(s.TunnelParameters)
	if err != nil {
		return err
	}
	fmt.Printf("隧道端点: %s；DTLS 1.2: %t；LZO: %t\n", p.Endpoint, p.DTLS12, p.Compression)
	return nil
}
