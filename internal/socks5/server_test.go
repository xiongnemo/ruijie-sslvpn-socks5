package socks5

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"
)

func startServer(t *testing.T, config Config) (string, context.CancelFunc, <-chan error) {
	t.Helper()
	s, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Errorf("Serve shutdown: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("server did not stop all handlers")
		}
	})
	return listener.Addr().String(), cancel, done
}

func connectClient(t *testing.T, address string, methods ...byte) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	hello := append([]byte{5, byte(len(methods))}, methods...)
	if err := writeAll(conn, hello); err != nil {
		t.Fatal(err)
	}
	return conn
}

func requireBytes(t *testing.T, conn io.Reader, want []byte) {
	t.Helper()
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func readReply(t *testing.T, conn io.Reader) byte {
	t.Helper()
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		t.Fatal(err)
	}
	if header[0] != 5 || header[2] != 0 {
		t.Fatalf("invalid reply header %v", header)
	}
	var length int
	switch header[3] {
	case 1:
		length = 4
	case 4:
		length = 16
	default:
		t.Fatalf("unexpected reply address type %d", header[3])
	}
	if _, err := io.CopyN(io.Discard, conn, int64(length+2)); err != nil {
		t.Fatal(err)
	}
	return header[1]
}

func domainRequest(host string, port uint16) []byte {
	raw := append([]byte{5, 1, 0, 3, byte(len(host))}, host...)
	return append(raw, byte(port>>8), byte(port))
}

func startEcho(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var handlers sync.WaitGroup
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			handlers.Add(1)
			go func() {
				defer handlers.Done()
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				io.Copy(conn, conn)
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		<-acceptDone
		handlers.Wait()
	})
	return listener.Addr().String()
}

func TestConnectUsesInjectedDialerAndPreservesDestination(t *testing.T) {
	echoAddress := startEcho(t)
	requests := []struct {
		name string
		raw  []byte
		want string
	}{
		{"domain", domainRequest("vpn-only.invalid", 443), "vpn-only.invalid:443"},
		{"IPv4", []byte{5, 1, 0, 1, 203, 0, 113, 17, 1, 187}, "203.0.113.17:443"},
		{"IPv6", append(append([]byte{5, 1, 0, 4}, net.ParseIP("2001:db8::17").To16()...), 1, 187), "[2001:db8::17]:443"},
	}
	for _, request := range requests {
		t.Run(request.name, func(t *testing.T) {
			observed := make(chan string, 1)
			address, _, _ := startServer(t, Config{DialContext: func(ctx context.Context, network, target string) (net.Conn, error) {
				if network != "tcp" {
					t.Errorf("network = %q", network)
				}
				observed <- target
				return (&net.Dialer{}).DialContext(ctx, "tcp", echoAddress)
			}})
			conn := connectClient(t, address, 0)
			requireBytes(t, conn, []byte{5, 0})
			payload := bytes.Repeat([]byte("VPN stream payload\x00\xff"), 4096)
			// A client may pipeline data with CONNECT. Parsing must not consume
			// any of the stream bytes beyond the request.
			packet := append(append([]byte(nil), request.raw...), payload[:97]...)
			if err := writeAll(conn, packet); err != nil {
				t.Fatal(err)
			}
			if code := readReply(t, conn); code != 0 {
				t.Fatalf("CONNECT failed: %d", code)
			}
			if got := <-observed; got != request.want {
				t.Fatalf("dial destination = %q, want %q", got, request.want)
			}
			if err := writeAll(conn, payload[97:]); err != nil {
				t.Fatal(err)
			}
			requireBytes(t, conn, payload)
		})
	}
}

func TestUsernamePasswordAuthentication(t *testing.T) {
	echoAddress := startEcho(t)
	for _, test := range []struct {
		name, user, password string
		status               byte
	}{
		{"valid", "alice", "correct horse", 0},
		{"wrong password", "alice", "incorrect", 1},
		{"wrong user", "mallory", "correct horse", 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			address, _, _ := startServer(t, Config{Username: "alice", Password: "correct horse", DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				if test.status != 0 {
					t.Error("failed authentication reached outbound dialer")
				}
				return (&net.Dialer{}).DialContext(ctx, "tcp", echoAddress)
			}})
			conn := connectClient(t, address, 0, 2)
			requireBytes(t, conn, []byte{5, 2})
			auth := append([]byte{1, byte(len(test.user))}, test.user...)
			auth = append(auth, byte(len(test.password)))
			auth = append(auth, test.password...)
			if err := writeAll(conn, auth); err != nil {
				t.Fatal(err)
			}
			requireBytes(t, conn, []byte{1, test.status})
			if test.status != 0 {
				var b [1]byte
				if _, err := conn.Read(b[:]); err == nil {
					t.Fatal("failed authentication connection was not closed")
				}
				return
			}
			if err := writeAll(conn, domainRequest("private.invalid", 80)); err != nil {
				t.Fatal(err)
			}
			if code := readReply(t, conn); code != 0 {
				t.Fatalf("CONNECT failed: %d", code)
			}
			writeAll(conn, []byte("authenticated"))
			requireBytes(t, conn, []byte("authenticated"))
		})
	}
}

func TestAuthenticationCannotBeDowngraded(t *testing.T) {
	address, _, _ := startServer(t, Config{Username: "alice", Password: "password", DialContext: func(context.Context, string, string) (net.Conn, error) {
		t.Error("unauthenticated request reached outbound dialer")
		return nil, errors.New("unexpected dial")
	}})
	conn := connectClient(t, address, 0)
	requireBytes(t, conn, []byte{5, 255})
}

func TestUnsupportedCommandsAndMalformedAddressesDoNotDial(t *testing.T) {
	address, _, _ := startServer(t, Config{DialContext: func(context.Context, string, string) (net.Conn, error) {
		t.Error("invalid request reached outbound dialer")
		return nil, errors.New("unexpected dial")
	}})
	for _, test := range []struct {
		name string
		raw  []byte
		code byte
	}{
		{"BIND", []byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0}, 7},
		{"UDP ASSOCIATE", []byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}, 7},
		{"unknown address", []byte{5, 1, 0, 99}, 8},
		{"empty domain", []byte{5, 1, 0, 3, 0}, 8},
		{"NUL in domain", domainRequest("bad\x00name", 80), 8},
		{"port zero", domainRequest("host.invalid", 0), 1},
		{"bad reserved byte", []byte{5, 1, 1, 1}, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			conn := connectClient(t, address, 0)
			requireBytes(t, conn, []byte{5, 0})
			writeAll(conn, test.raw)
			if code := readReply(t, conn); code != test.code {
				t.Fatalf("reply = %d, want %d", code, test.code)
			}
		})
	}
}

func TestDialFailureReplies(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		code byte
	}{
		{"refused", &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}, 5},
		{"network unreachable", syscall.ENETUNREACH, 3},
		{"host unreachable", syscall.EHOSTUNREACH, 4},
		{"DNS", &net.DNSError{Err: "unreachable", Name: "private.invalid"}, 4},
		{"other", errors.New("VPN unavailable"), 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			address, _, _ := startServer(t, Config{DialContext: func(context.Context, string, string) (net.Conn, error) { return nil, test.err }})
			conn := connectClient(t, address, 0)
			requireBytes(t, conn, []byte{5, 0})
			writeAll(conn, domainRequest("private.invalid", 80))
			if code := readReply(t, conn); code != test.code {
				t.Fatalf("reply = %d, want %d", code, test.code)
			}
		})
	}
}

func TestConnectTimeoutCancelsDial(t *testing.T) {
	address, _, _ := startServer(t, Config{ConnectTimeout: 40 * time.Millisecond, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}})
	conn := connectClient(t, address, 0)
	requireBytes(t, conn, []byte{5, 0})
	writeAll(conn, domainRequest("private.invalid", 80))
	if code := readReply(t, conn); code != 4 {
		t.Fatalf("timeout reply = %d, want 4", code)
	}
}

func TestHandshakeTimeoutAndConnectionLimit(t *testing.T) {
	address, _, _ := startServer(t, Config{MaxConnections: 1, HandshakeTimeout: 100 * time.Millisecond, DialContext: func(context.Context, string, string) (net.Conn, error) {
		t.Error("incomplete handshake reached dialer")
		return nil, errors.New("unexpected dial")
	}})
	first := connectClient(t, address, 0)
	requireBytes(t, first, []byte{5, 0})
	second, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	second.SetReadDeadline(time.Now().Add(5 * time.Second))
	var b [1]byte
	if _, err := second.Read(b[:]); err == nil {
		t.Fatal("connection over the limit was not closed")
	}
	if _, err := first.Read(b[:]); err == nil {
		t.Fatal("incomplete handshake did not time out")
	}
}

func TestShutdownClosesActiveRelayAndCancelsPendingDial(t *testing.T) {
	echoAddress := startEcho(t)
	dialStarted := make(chan struct{})
	dialCanceled := make(chan struct{})
	address, cancel, _ := startServer(t, Config{DialContext: func(ctx context.Context, _, target string) (net.Conn, error) {
		if target == "pending.invalid:80" {
			close(dialStarted)
			<-ctx.Done()
			close(dialCanceled)
			return nil, ctx.Err()
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", echoAddress)
	}})
	active := connectClient(t, address, 0)
	requireBytes(t, active, []byte{5, 0})
	writeAll(active, domainRequest("active.invalid", 80))
	if code := readReply(t, active); code != 0 {
		t.Fatalf("active CONNECT failed: %d", code)
	}
	writeAll(active, []byte("ready"))
	requireBytes(t, active, []byte("ready"))
	pending := connectClient(t, address, 0)
	requireBytes(t, pending, []byte{5, 0})
	writeAll(pending, domainRequest("pending.invalid", 80))
	select {
	case <-dialStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("dialer did not start")
	}
	// This third client is still inside the greeting handshake.
	idle, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	cancel()
	select {
	case <-dialCanceled:
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown did not cancel the VPN dialer")
	}
	for _, conn := range []net.Conn{active, idle} {
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		var b [1]byte
		if _, err := conn.Read(b[:]); err == nil {
			t.Fatal("shutdown left a client open")
		} else if e, ok := err.(net.Error); ok && e.Timeout() {
			t.Fatal("shutdown client close timed out")
		}
	}
}

func TestTCPHalfCloseAllowsFinalResponse(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	targetDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			targetDone <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		data, err := io.ReadAll(conn)
		if err == nil {
			err = writeAll(conn, append([]byte("received:"), data...))
		}
		targetDone <- err
	}()
	address, _, _ := startServer(t, Config{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
	}})
	client := connectClient(t, address, 0)
	requireBytes(t, client, []byte{5, 0})
	writeAll(client, domainRequest("private.invalid", 80))
	if code := readReply(t, client); code != 0 {
		t.Fatalf("CONNECT failed: %d", code)
	}
	writeAll(client, []byte("request body"))
	if err := client.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	requireBytes(t, client, []byte("received:request body"))
	if err := <-targetDone; err != nil {
		t.Fatal(err)
	}
}

func TestConfigValidation(t *testing.T) {
	dial := func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("unused") }
	for _, config := range []Config{
		{},
		{DialContext: dial, Username: "alice"},
		{DialContext: dial, Password: "password"},
		{DialContext: dial, HandshakeTimeout: -time.Second},
		{DialContext: dial, ConnectTimeout: -time.Second},
		{DialContext: dial, MaxConnections: -1},
		{DialContext: dial, Username: string(bytes.Repeat([]byte{'u'}, 256)), Password: "password"},
	} {
		if _, err := New(config); err == nil {
			t.Errorf("accepted invalid configuration %+v", config)
		}
	}
}

func TestSuccessReplyCarriesBoundAddress(t *testing.T) {
	for _, addr := range []*net.TCPAddr{
		{IP: net.ParseIP("192.0.2.123"), Port: 40000},
		{IP: net.ParseIP("2001:db8::123"), Port: 40000},
	} {
		var buf bytes.Buffer
		if err := writeReply(&buf, 0, addr); err != nil {
			t.Fatal(err)
		}
		raw := buf.Bytes()
		if port := binary.BigEndian.Uint16(raw[len(raw)-2:]); port != 40000 {
			t.Fatalf("bound port = %d", port)
		}
		if ip := net.IP(raw[4 : len(raw)-2]); !ip.Equal(addr.IP) {
			t.Fatalf("bound IP = %s, want %s", ip, addr.IP)
		}
	}
}
