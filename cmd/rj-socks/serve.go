package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"

	"github.com/xiongnemo/ruijie-sslvpn-socks5/internal/config"
	"github.com/xiongnemo/ruijie-sslvpn-socks5/internal/dtlstransport"
	"github.com/xiongnemo/ruijie-sslvpn-socks5/internal/netstack"
	"github.com/xiongnemo/ruijie-sslvpn-socks5/internal/socks5"
	"github.com/xiongnemo/ruijie-sslvpn-socks5/internal/tunnel"
	"github.com/xiongnemo/ruijie-sslvpn-socks5/internal/vpnauth"
)

func serveVPN(ctx context.Context, c config.Config, tc *tls.Config, sess *vpnauth.Session) error {
	params, err := tunnel.ParseParameters(sess.TunnelParameters)
	if err != nil {
		return err
	}
	if !params.DTLS12 {
		return errors.New("网关仅宣告 DTLS 1.0，尚未完成该版本的 Go 兼容实现")
	}
	fmt.Printf("建立 DTLS 隧道至 %s…\n", params.Endpoint)
	handshake, cancelHandshake := context.WithTimeout(ctx, c.Timeouts.Handshake)
	conn, err := dtlstransport.Dial(handshake, params.Endpoint, params.Secret, tc)
	cancelHandshake()
	if err != nil {
		return fmt.Errorf("DTLS handshake: %w", err)
	}
	link, assigned, err := tunnel.Connect(ctx, conn, params.SessionID, tunnel.Options{Compression: params.Compression, ExtendedHeartbeat: sess.ExtendedHeartbeat, Timeout: c.Timeouts.Handshake})
	if err != nil {
		conn.Close()
		return err
	}
	defer link.Close()
	network, err := netstack.New(ctx, assigned.Address, assigned.DNS, assigned.MTU, link)
	if err != nil {
		return err
	}
	defer network.Close()
	server, err := socks5.New(socks5.Config{DialContext: network.DialContext, Username: c.SOCKS5.Username, Password: c.SOCKS5.Password, MaxConnections: c.SOCKS5.MaxConnections, HandshakeTimeout: c.Timeouts.Handshake, ConnectTimeout: c.Timeouts.Connect})
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", c.SOCKS5.Listen)
	if err != nil {
		return err
	}
	serviceCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-link.Done():
			cancel()
		case <-network.Done():
			cancel()
		case <-serviceCtx.Done():
		}
	}()
	fmt.Printf("VPN 已连接，虚拟 IP %s，DNS %v，SOCKS5 监听 %s\n", assigned.Address, assigned.DNS, listener.Addr())
	err = server.Serve(serviceCtx, listener)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	select {
	case <-link.Done():
		return link.Err()
	default:
	}
	select {
	case <-network.Done():
		return network.Err()
	default:
	}
	return err
}
