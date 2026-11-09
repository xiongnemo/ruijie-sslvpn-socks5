// Package netstack implements TCP and DNS over the VPN's raw IPv4 packets.
// It creates no host interfaces, routes, or sockets.
package netstack

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// PacketLink exchanges complete IPv4 datagrams, without Ethernet headers.
// ReadPacket must respect context cancellation. WritePacket must copy or finish
// consuming its input before returning and must have a bounded write deadline.
// The caller owns and closes the link; Network.Close does not close it.
type PacketLink interface {
	ReadPacket(context.Context) ([]byte, error)
	WritePacket([]byte) error
}

// Network is an isolated userspace IPv4 stack. It closes all connections on
// cancellation or link failure; it never falls back to the host's network.
type Network struct {
	stack  *stack.Stack
	ep     *channel.Endpoint
	dns    []netip.Addr
	ctx    context.Context
	cancel context.CancelCauseFunc
	mu     sync.RWMutex // excludes stack shutdown from endpoint creation/injection
	once   sync.Once
	wg     sync.WaitGroup
}

// New creates a stack using the virtual address and DNS servers negotiated by
// the VPN. An empty DNS list permits IP connections but rejects domain names.
func New(ctx context.Context, address netip.Addr, dns []netip.Addr, mtu uint32, link PacketLink) (*Network, error) {
	if ctx == nil || link == nil {
		return nil, errors.New("netstack: context and packet link are required")
	}
	address = address.Unmap()
	if !address.Is4() || address.IsUnspecified() || address.IsMulticast() {
		return nil, errors.New("netstack: a valid VPN-assigned unicast IPv4 address is required")
	}
	if mtu < 576 || mtu > 65535 {
		return nil, errors.New("netstack: MTU must be between 576 and 65535")
	}
	servers := make([]netip.Addr, 0, len(dns))
	for _, ip := range dns {
		ip = ip.Unmap()
		if !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() {
			return nil, fmt.Errorf("netstack: invalid IPv4 DNS server %s", ip)
		}
		servers = append(servers, ip)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	n := &Network{dns: servers, ep: channel.New(1024, mtu, "")}
	n.ctx, n.cancel = context.WithCancelCause(ctx)
	n.stack = stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4},
		HandleLocal:        true,
	})
	fail := func(err tcpip.Error) (*Network, error) {
		n.cancel(errors.New(err.String()))
		n.ep.Close()
		n.stack.Destroy()
		return nil, fmt.Errorf("netstack: %s", err.String())
	}
	sack := tcpip.TCPSACKEnabled(true)
	if err := n.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &sack); err != nil {
		return fail(err)
	}
	if err := n.stack.CreateNIC(1, n.ep); err != nil {
		return fail(err)
	}
	if err := n.stack.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFromSlice(address.AsSlice()).WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		return fail(err)
	}
	n.stack.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	n.wg.Add(2)
	go n.receive(link)
	go n.send(link)
	go func() { <-n.ctx.Done(); _ = n.Close() }()
	return n, nil
}

func (n *Network) receive(link PacketLink) {
	defer n.wg.Done()
	for {
		p, err := link.ReadPacket(n.ctx)
		if err != nil {
			n.cancel(fmt.Errorf("read VPN packet: %w", err))
			return
		}
		if n.ctx.Err() != nil {
			return
		}
		// Reject invalid envelopes before exposing untrusted input to the stack.
		if len(p) < 20 || len(p) > 65535 || p[0]>>4 != 4 {
			continue
		}
		hlen := int(p[0]&15) * 4
		if hlen < 20 || len(p) < hlen || int(binary.BigEndian.Uint16(p[2:4])) != len(p) {
			continue
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(p)})
		n.mu.RLock()
		if n.ctx.Err() == nil {
			n.ep.InjectInbound(ipv4.ProtocolNumber, pkt)
		}
		n.mu.RUnlock()
		pkt.DecRef()
	}
}

func (n *Network) send(link PacketLink) {
	defer n.wg.Done()
	for {
		pkt := n.ep.ReadContext(n.ctx)
		if pkt == nil {
			return
		}
		if n.ctx.Err() != nil {
			pkt.DecRef()
			return
		}
		view := pkt.ToView()
		pkt.DecRef()
		err := link.WritePacket(view.AsSlice())
		view.Release()
		if err != nil {
			n.cancel(fmt.Errorf("write VPN packet: %w", err))
			return
		}
	}
}

// Done is closed when the parent context, link, or network closes.
func (n *Network) Done() <-chan struct{} { return n.ctx.Done() }

// Err reports the reason for closure, or nil while the network is running.
func (n *Network) Err() error { return context.Cause(n.ctx) }

// Close cancels pending dials, aborts live sockets, and releases stack workers.
func (n *Network) Close() error {
	n.once.Do(func() {
		n.cancel(net.ErrClosed)
		n.mu.Lock()
		n.ep.Close()
		n.stack.Close()
		n.mu.Unlock()
		n.wg.Wait()
		n.stack.Wait()
	})
	return nil
}

func fullAddress(ip netip.Addr, port uint16) tcpip.FullAddress {
	return tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(ip.AsSlice()), Port: port}
}

// DialContext opens TCP through the VPN. Domains are resolved exclusively using
// the VPN DNS servers; IPv6 and non-TCP requests are explicitly unsupported.
func (n *Network) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" {
		return nil, net.UnknownNetworkError(network)
	}
	host, service, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(service, 10, 16)
	if err != nil || port == 0 {
		return nil, fmt.Errorf("netstack: invalid TCP port %q", service)
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(n.ctx, cancel)
	defer stop()
	defer cancel()
	n.mu.RLock()
	defer n.mu.RUnlock()
	if err := n.ctx.Err(); err != nil {
		return nil, n.Err()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var addresses []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if !ip.Is4() {
			return nil, errors.New("netstack: VPN transport supports IPv4 only")
		}
		addresses = []netip.Addr{ip}
	} else {
		addresses, err = n.lookupIPv4(ctx, host)
		if err != nil {
			return nil, err
		}
	}
	var last error
	for _, ip := range addresses {
		conn, err := gonet.DialContextTCP(ctx, n.stack, fullAddress(ip, uint16(port)), ipv4.ProtocolNumber)
		if err == nil {
			return conn, nil
		}
		last = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, last
}
