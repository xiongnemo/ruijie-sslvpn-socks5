package netstack

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

type memoryLink struct {
	rx, tx     chan []byte
	ctx        context.Context
	packets    atomic.Int64
	dnsPackets atomic.Int64
}

func (l *memoryLink) ReadPacket(ctx context.Context) ([]byte, error) {
	select {
	case p := <-l.rx:
		return p, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (l *memoryLink) WritePacket(p []byte) error {
	l.packets.Add(1)
	if len(p) >= 28 && p[9] == 17 {
		hlen := int(p[0]&15) * 4
		if len(p) >= hlen+8 && binary.BigEndian.Uint16(p[hlen+2:hlen+4]) == 53 {
			l.dnsPackets.Add(1)
		}
	}
	select {
	case l.tx <- bytes.Clone(p):
		return nil
	case <-l.ctx.Done():
		return l.ctx.Err()
	}
}

func stackPair(t *testing.T, dns bool) (*Network, *Network, *memoryLink) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	a, b := make(chan []byte, 1024), make(chan []byte, 1024)
	linkA, linkB := &memoryLink{rx: a, tx: b, ctx: ctx}, &memoryLink{rx: b, tx: a, ctx: ctx}
	var servers []netip.Addr
	if dns {
		servers = []netip.Addr{netip.MustParseAddr("10.77.0.1")}
	}
	client, err := New(ctx, netip.MustParseAddr("10.77.0.2"), servers, 1280, linkA)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	server, err := New(ctx, netip.MustParseAddr("10.77.0.1"), nil, 1280, linkB)
	if err != nil {
		_ = client.Close()
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = client.Close(); _ = server.Close() })
	return client, server, linkA
}

func echoListener(t *testing.T, n *Network) net.Listener {
	t.Helper()
	listener, err := gonet.ListenTCP(n.stack, fullAddress(netip.MustParseAddr("10.77.0.1"), 12345), ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return listener
}

func roundTrip(t *testing.T, n *Network, address string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := n.DialContext(ctx, "tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	// Several MTUs of data exercise TCP segmentation and reassembly.
	payload := bytes.Repeat([]byte("VPN userspace echo\x00"), 2000)
	writeDone := make(chan error, 1)
	go func() { _, err := io.Copy(c, bytes.NewReader(payload)); writeDone <- err }()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("corrupted TCP payload")
	}
}

func TestTCPAcrossRawIPLink(t *testing.T) {
	client, server, link := stackPair(t, false)
	_ = echoListener(t, server)
	link.rx <- []byte{0xff} // malformed inbound data is ignored
	roundTrip(t, client, "10.77.0.1:12345")
	if link.packets.Load() < 4 {
		t.Fatal("expected raw IP packets to cross the link")
	}
}

func TestDNSAndTCPStayInsideTunnel(t *testing.T) {
	client, server, link := stackPair(t, true)
	_ = echoListener(t, server)
	dns, err := gonet.DialUDP(server.stack, ptrFullAddress("10.77.0.1", 53), nil, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dns.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := dns.ReadFrom(buf)
			if err != nil {
				return
			}
			var q dnsmessage.Message
			if q.Unpack(buf[:n]) != nil || len(q.Questions) != 1 {
				continue
			}
			answer := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true, RecursionAvailable: true}, Questions: q.Questions, Answers: []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{10, 77, 0, 1}}}}}
			p, err := answer.Pack()
			if err == nil {
				_, _ = dns.WriteTo(p, addr)
			}
		}
	}()
	// .invalid must never resolve through host DNS; the isolated server resolves it.
	roundTrip(t, client, "private-vpn-name.invalid:12345")
	if link.dnsPackets.Load() == 0 {
		t.Fatal("DNS did not traverse the packet link")
	}
}

func TestTruncatedDNSUsesTunnelTCPAndCNAME(t *testing.T) {
	client, server, _ := stackPair(t, true)
	_ = echoListener(t, server)
	dns, err := gonet.DialUDP(server.stack, ptrFullAddress("10.77.0.1", 53), nil, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dns.Close() })
	tcpDNS, err := gonet.ListenTCP(server.stack, *ptrFullAddress("10.77.0.1", 53), ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tcpDNS.Close() })
	served := make(chan error, 1)
	go func() {
		buf := make([]byte, 512)
		n, addr, err := dns.ReadFrom(buf)
		if err != nil {
			return
		}
		var q dnsmessage.Message
		if q.Unpack(buf[:n]) != nil {
			return
		}
		response, _ := (&dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true, Truncated: true}, Questions: q.Questions}).Pack()
		_, _ = dns.WriteTo(response, addr)
	}()
	go func() {
		c, err := tcpDNS.Accept()
		if err != nil {
			served <- err
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		var length [2]byte
		if _, err = io.ReadFull(c, length[:]); err != nil {
			served <- err
			return
		}
		p := make([]byte, int(binary.BigEndian.Uint16(length[:])))
		if _, err = io.ReadFull(c, p); err != nil {
			served <- err
			return
		}
		var q dnsmessage.Message
		if err = q.Unpack(p); err != nil {
			served <- err
			return
		}
		alias := dnsmessage.MustNewName("vpn-alias.invalid.")
		response := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true}, Questions: q.Questions, Answers: []dnsmessage.Resource{
			{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("unrelated.invalid."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}, Body: &dnsmessage.AResource{A: [4]byte{10, 77, 0, 99}}},
			{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET}, Body: &dnsmessage.CNAMEResource{CNAME: alias}},
			{Header: dnsmessage.ResourceHeader{Name: alias, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}, Body: &dnsmessage.AResource{A: [4]byte{10, 77, 0, 1}}},
		}}
		p, err = response.Pack()
		if err != nil {
			served <- err
			return
		}
		binary.BigEndian.PutUint16(length[:], uint16(len(p)))
		_, err = io.Copy(c, bytes.NewReader(append(length[:], p...)))
		served <- err
	}()
	roundTrip(t, client, "cname-vpn-name.invalid:12345")
	select {
	case err := <-served:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("DNS TCP handler did not complete")
	}
}

func ptrFullAddress(ip string, port uint16) *tcpip.FullAddress {
	a := fullAddress(netip.MustParseAddr(ip), port)
	return &a
}

func TestNoDNSOrIPv6Fallback(t *testing.T) {
	client, _, link := stackPair(t, false)
	for _, address := range []string{"private-vpn-name.invalid:80", "[2001:db8::1]:80"} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_, err := client.DialContext(ctx, "tcp", address)
		cancel()
		if err == nil {
			t.Fatalf("expected rejection for %s", address)
		}
	}
	if got := link.packets.Load(); got != 0 {
		t.Fatalf("unexpected fallback packets: %d", got)
	}
}

func TestCloseCancelsPendingDialAndSockets(t *testing.T) {
	client, server, _ := stackPair(t, false)
	_ = echoListener(t, server)
	c, err := client.DialContext(context.Background(), "tcp", "10.77.0.1:12345")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	dialDone := make(chan error, 1)
	go func() { _, err := client.DialContext(context.Background(), "tcp", "10.77.0.99:80"); dialDone <- err }()
	closed := make(chan struct{})
	go func() { _ = client.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("Close blocked")
	}
	select {
	case err := <-dialDone:
		if err == nil {
			t.Fatal("pending dial succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("dial not cancelled")
	}
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("active socket not closed")
	}
	if !errors.Is(client.Err(), net.ErrClosed) {
		t.Fatalf("closure cause: %v", client.Err())
	}
	if _, err := client.DialContext(context.Background(), "tcp", "10.77.0.1:12345"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("post-close dial: %v", err)
	}
}

func TestValidateNetworkParameters(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	link := &memoryLink{ctx: ctx, rx: make(chan []byte), tx: make(chan []byte)}
	for _, ip := range []string{"0.0.0.0", "::1", "224.0.0.1"} {
		if n, err := New(ctx, netip.MustParseAddr(ip), nil, 1400, link); err == nil {
			_ = n.Close()
			t.Fatalf("accepted %s", ip)
		}
	}
	if n, err := New(ctx, netip.MustParseAddr("10.0.0.1"), nil, 100, link); err == nil {
		_ = n.Close()
		t.Fatal("accepted tiny MTU")
	}
}
