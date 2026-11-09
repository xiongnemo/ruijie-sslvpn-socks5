package dtlstransport

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

func TestCookieMatchesNativeHMACSHA1(t *testing.T) {
	secret := make([]byte, 16)
	challenge := make([]byte, 20)
	for i := range secret {
		secret[i] = byte(i)
	}
	for i := range challenge {
		challenge[i] = byte(i + 16)
	}
	before := bytes.Clone(challenge)
	hook := cookieHook(secret)
	got := hook(handshake.MessageClientHello{Cookie: challenge}).(*handshake.MessageClientHello)
	// Independent Python/OpenSSL HMAC-SHA1 test vector.
	if hex.EncodeToString(got.Cookie) != "daa5de1c11d436dd6ea8c64df6936f764bbedd07" {
		t.Fatalf("incorrect HMAC: %x", got.Cookie)
	}
	if !bytes.Equal(challenge, before) {
		t.Fatal("hook mutated cached source challenge")
	}
	for _, size := range []int{0, 1, 16, 19, 21, 255} {
		cookie := bytes.Repeat([]byte{0x27}, size)
		got := hook(handshake.MessageClientHello{Cookie: cookie}).(*handshake.MessageClientHello)
		if !bytes.Equal(got.Cookie, cookie) {
			t.Fatalf("native length condition violated for %d", size)
		}
	}
}

func decodeHello(p []byte) (*handshake.MessageClientHello, error) {
	records, err := recordlayer.UnpackDatagram(p)
	if err != nil {
		return nil, err
	}
	for _, record := range records {
		var layer recordlayer.RecordLayer
		if err = layer.Unmarshal(record); err != nil {
			return nil, err
		}
		if h, ok := layer.Content.(*handshake.Handshake); ok {
			if hello, ok := h.Message.(*handshake.MessageClientHello); ok {
				return hello, nil
			}
		}
	}
	return nil, errors.New("no client hello")
}

func TestUDPHelloVerifyCookieOnWire(t *testing.T) {
	for _, size := range []int{16, 20} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			server, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			_ = server.SetDeadline(time.Now().Add(4 * time.Second))
			endpoint := server.LocalAddr().(*net.UDPAddr).AddrPort()
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			secret := bytes.Repeat([]byte{0x14}, 16)
			challenge := bytes.Repeat([]byte{0x37}, size)
			captured := make(chan error, 1)
			go func() {
				buf := make([]byte, 4096)
				n, addr, err := server.ReadFrom(buf)
				if err != nil {
					captured <- err
					return
				}
				first, err := decodeHello(buf[:n])
				if err != nil {
					captured <- err
					return
				}
				if len(first.Cookie) != 0 || len(first.SessionID) != 0 {
					captured <- errors.New("first hello unexpectedly includes auth cookie/session ID")
					return
				}
				verify := recordlayer.RecordLayer{Header: recordlayer.Header{Version: protocol.Version1_0}, Content: &handshake.Handshake{Message: &handshake.MessageHelloVerifyRequest{Version: protocol.Version1_0, Cookie: challenge}}}
				p, err := verify.Marshal()
				if err != nil {
					captured <- err
					return
				}
				if _, err = server.WriteTo(p, addr); err != nil {
					captured <- err
					return
				}
				for {
					n, _, err = server.ReadFrom(buf)
					if err != nil {
						captured <- err
						return
					}
					hello, err := decodeHello(buf[:n])
					if err != nil {
						continue
					}
					if len(hello.Cookie) == 0 {
						continue
					}
					expected := cookieHook(secret)(handshake.MessageClientHello{Cookie: challenge}).(*handshake.MessageClientHello).Cookie
					if !bytes.Equal(hello.Cookie, expected) {
						captured <- fmt.Errorf("wire cookie differs: %x", hello.Cookie)
						return
					}
					if len(hello.SessionID) != 0 {
						captured <- errors.New("application session ID leaked into DTLS ClientHello")
						return
					}
					captured <- nil
					cancel()
					return
				}
			}()
			conn, err := Dial(ctx, endpoint, secret, &tls.Config{InsecureSkipVerify: true})
			if conn != nil {
				_ = conn.Close()
			}
			if err == nil {
				t.Fatal("capture-only peer must not complete handshake")
			}
			if captureErr := <-captured; captureErr != nil {
				t.Fatal(captureErr)
			}
		})
	}
}

func testCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(7), DNSNames: []string{"vpn.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: parsed}, pool
}

func echoDTLS(t *testing.T) (netip.AddrPort, *x509.CertPool) {
	t.Helper()
	cert, pool := testCertificate(t)
	listener, err := dtls.ListenWithOptions("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, dtls.WithCertificates(cert), dtls.WithInsecureSkipVerifyHello(true))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		c, err := listener.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err = c.(*dtls.Conn).HandshakeContext(ctx); err != nil {
			return
		}
		buf := make([]byte, 1024)
		n, err := c.Read(buf)
		if err == nil {
			_, _ = c.Write(buf[:n])
		}
	}()
	return listener.Addr().(*net.UDPAddr).AddrPort(), pool
}

func TestDTLSHandshakeEchoAndCertificatePolicy(t *testing.T) {
	endpoint, pool := echoDTLS(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	var peerCalled, connectionCalled atomic.Bool
	config := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "vpn.test", RootCAs: pool,
		VerifyPeerCertificate: func(raw [][]byte, chains [][]*x509.Certificate) error {
			if len(raw) == 0 || len(chains) == 0 {
				return errors.New("certificate verification was skipped")
			}
			peerCalled.Store(true)
			return nil
		},
		VerifyConnection: func(cs tls.ConnectionState) error {
			if cs.Version != tls.VersionTLS12 || cs.ServerName != "vpn.test" || len(cs.PeerCertificates) != 1 || len(cs.VerifiedChains) == 0 {
				return errors.New("DTLS connection state lost certificate policy")
			}
			connectionCalled.Store(true)
			return nil
		},
	}
	conn, err := Dial(ctx, endpoint, make([]byte, 16), config)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	message := []byte("encrypted VPN datagram")
	if _, err = conn.Write(message); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(message))
	if _, err = io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, message) {
		t.Fatal("DTLS echo corrupted")
	}
	if !peerCalled.Load() || !connectionCalled.Load() {
		t.Fatal("verification callbacks not preserved")
	}
}

func TestDTLSRejectsPinFailure(t *testing.T) {
	endpoint, _ := echoDTLS(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	pinError := errors.New("pinned certificate mismatch")
	conn, err := Dial(ctx, endpoint, make([]byte, 16), &tls.Config{InsecureSkipVerify: true, VerifyConnection: func(tls.ConnectionState) error { return pinError }})
	if conn != nil {
		_ = conn.Close()
		t.Fatal("returned connection after failed pin policy")
	}
	if !errors.Is(err, pinError) {
		t.Fatalf("pin error not preserved: %v", err)
	}
}

func TestDTLSPendingHandshakeCancellation(t *testing.T) {
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = Dial(ctx, server.LocalAddr().(*net.UDPAddr).AddrPort(), make([]byte, 16), &tls.Config{InsecureSkipVerify: true})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancellation: %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("handshake did not respect cancellation")
	}
}
