package dtlstransport

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/prf"
	"github.com/pion/dtls/v3/pkg/protocol/recordlayer"
)

func sha384Material() (master, client, server []byte) {
	master, client, server = make([]byte, 48), make([]byte, 32), make([]byte, 32)
	for i := range master {
		master[i] = byte(i)
	}
	for i := range client {
		client[i], server[i] = byte(i), byte(i+32)
	}
	return
}

func unhex(t *testing.T, text string) []byte {
	t.Helper()
	value, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestSHA384OpenSSLKeyExpansionVector(t *testing.T) {
	// Independent OpenSSL 4.1.0 TLS1-PRF output, not another Pion endpoint:
	// openssl kdf -keylen 192 -kdfopt digest:SHA384 -kdfopt hexsecret:<00..2f>
	//   -kdfopt hexseed:<"key expansion" || 20..3f || 00..1f> TLS1-PRF
	const keyBlock = "de545e3a55fc37510a2c9f4823c15511bc0497d6e1245e15574209a947c083510cdaf95bc7a2a184989c633771e022fa" +
		"683a0c6e362a908f7da3715ca40516a3c241a06da740d7a59487c1541a4c8af4a29dc834e443d8f9a39fa471c27108ad" +
		"8b262608fe3e6aff55b739b8a2a59638a36126dd12a396cf086ad2f48e898bd6" +
		"e22326235fab2e096d54b0d4057f39a2f81ad1d82d8cbae1c28bdf698e3e2784" +
		"c549bf28cf2debdd4fb0c77a7915c2858" + "5554d79f325784d836a12358942c4ac"
	master, client, server := sha384Material()
	suite := gatewayCipherSuites()[0]
	keys, err := prf.GenerateEncryptionKeys(master, client, server, 48, 32, 16, suite.HashFunc())
	if err != nil {
		t.Fatal(err)
	}
	var actual []byte
	for _, key := range [][]byte{keys.ClientMACKey, keys.ServerMACKey, keys.ClientWriteKey, keys.ServerWriteKey, keys.ClientWriteIV, keys.ServerWriteIV} {
		actual = append(actual, key...)
	}
	if !bytes.Equal(actual, unhex(t, keyBlock)) {
		t.Fatal("SHA384 key expansion differs from independent OpenSSL vector")
	}
}

func TestSHA384OpenSSLRecordAndInvalidMAC(t *testing.T) {
	// Fixed client->server record: epoch1, sequence0x010203040506, explicit
	// IVf0..ff. Python hmac(SHA384) built the MAC over the DTLS sequence,
	// type/version/length and plaintext; OpenSSL enc -aes-256-cbc -nopad
	// encrypted the plaintext || MAC || TLS padding using the PRF vector key.
	const valid = "17fefd00010102030405060070f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff6b7d7b8c8264a69a8c4d2d771af10e09acf79afd9229c8fd1e137577d1f11807b33ea691417b61faf4af07f7e73be15d4d1588aa842b577018224388705cda4ae10d87a80b45ca434c30808cda16606c37c450e423bec5aee26463d8a87cf313"
	// Same independent record with exactly one MAC byte changed before CBC
	// encryption. The plaintext and valid padding are otherwise unchanged.
	const invalidMAC = "17fefd00010102030405060070f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff6b7d7b8c8264a69a8c4d2d771af10e09acf79afd9229c8fd1e137577d1f118079739b377fe68c4adad6e46d9898c215bae4eb6b6af633f654f2ba462377a8cfe01cbb8121527b5a22073ee0358d66012765a0bbeb17ecf2dcd38df4457e84b7c"
	master, client, server := sha384Material()
	suite := gatewayCipherSuites()[0]
	if err := suite.Init(master, client, server, false); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, raw string
		valid     bool
	}{
		{"OpenSSL record", valid, true},
		{"bad MAC with valid padding", invalidMAC, false},
		{"truncated record", valid[:len(valid)-2], false},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := unhex(t, test.raw)
			var header recordlayer.Header
			if err := header.Unmarshal(input); err != nil {
				t.Fatal(err)
			}
			plain, err := suite.Decrypt(header, input)
			if !test.valid {
				if err == nil || plain != nil {
					t.Fatal("accepted corrupted authenticated CBC record")
				}
				return
			}
			if err != nil || !bytes.Equal(plain[header.Size():], []byte("independent OpenSSL DTLS record\x00\xff")) {
				t.Fatalf("independent record decryption failed: %v", err)
			}
		})
	}
}

func TestSHA384FactoryStateAndUninitializedErrors(t *testing.T) {
	first, second := gatewayCipherSuites()[0], gatewayCipherSuites()[0]
	if first == second || first.IsInitialized() || second.IsInitialized() {
		t.Fatal("cipher suite factory reused connection state")
	}
	if _, err := first.Encrypt(nil, nil); !errors.Is(err, errCipherNotInitialized) {
		t.Fatal("uninitialized encryption did not return an error")
	}
	if _, err := first.Decrypt(recordlayer.Header{}, nil); !errors.Is(err, errCipherNotInitialized) {
		t.Fatal("uninitialized decryption did not return an error")
	}
}

func rsaSHA384Certificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(111), DNSNames: []string{"vpn.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}, pool
}

func TestSHA384DialHonorsExplicitCipherSuite(t *testing.T) {
	cert, pool := rsaSHA384Certificate(t)
	listener, err := dtls.ListenWithOptions("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, dtls.WithCertificates(cert), dtls.WithCustomCipherSuites(gatewayCipherSuites), dtls.WithInsecureSkipVerifyHello(true))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		if err = conn.(*dtls.Conn).HandshakeContext(ctx); err == nil {
			var data [256]byte
			var n int
			if n, err = conn.Read(data[:]); err == nil {
				_, err = conn.Write(data[:n])
			}
		}
		done <- err
	}()
	conn, err := Dial(ctx, listener.Addr().(*net.UDPAddr).AddrPort(), make([]byte, 16), &tls.Config{ServerName: "vpn.test", RootCAs: pool, CipherSuites: []uint16{uint16(gatewayCipherSuiteID)}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if state, ok := conn.(*dtls.Conn).ConnectionState(); !ok || state.CipherSuiteID != gatewayCipherSuiteID {
		t.Fatal("explicit cipher policy was not honored")
	}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	message := []byte("explicit SHA384 suite\x00\xff")
	if _, err := conn.Write(message); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, len(message))
	if _, err := io.ReadFull(conn, echo); err != nil || !bytes.Equal(echo, message) {
		t.Fatalf("explicit-suite echo failed: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSHA384OpenSSLDTLSHandshakeAndData(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("OpenSSL is unavailable; independent static key/record vectors still run")
	}
	cert, pool := rsaSHA384Certificate(t)
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(cert.PrivateKey.(*rsa.PrivateKey))}), 0600); err != nil {
		t.Fatal(err)
	}
	reservation, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	endpoint := reservation.LocalAddr().(*net.UDPAddr).AddrPort()
	reservation.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, openssl, "s_server", "-dtls1_2", "-accept", endpoint.String(), "-cipher", "ECDHE-RSA-AES256-SHA384", "-cert", certFile, "-key", keyFile, "-quiet", "-state", "-naccept", "1")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr, err := os.Create(filepath.Join(dir, "openssl.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer stderr.Close()
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	defer func() {
		cancel()
		<-done
		if t.Failed() {
			data, _ := os.ReadFile(stderr.Name())
			t.Logf("OpenSSL diagnostic: %s", data)
		}
	}()
	// An initial lost UDP datagram while OpenSSL binds is retransmitted by DTLS.
	time.Sleep(50 * time.Millisecond)
	// Windows s_server needs pending stdin to enter its SSL_accept loop.
	// Queue a server message, then independently check both data directions.
	serverMessage := []byte("x server OpenSSL CBC SHA384 data\n")
	if _, err := stdin.Write(serverMessage); err != nil {
		t.Fatal(err)
	}
	// A standard OpenSSL server verifies its original cookie rather than the
	// VPN's HMAC-transformed cookie. Exercise the new suite directly here;
	// the production hook has its separate raw-UDP wire regression test.
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	conn, err := dtls.ClientWithOptions(packet, net.UDPAddrFromAddrPort(endpoint), dtls.WithServerName("vpn.test"), dtls.WithRootCAs(pool), dtls.WithCustomCipherSuites(gatewayCipherSuites))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	if state, ok := conn.ConnectionState(); !ok || state.CipherSuiteID != gatewayCipherSuiteID {
		t.Fatal("OpenSSL negotiated the wrong cipher suite")
	}
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	message := []byte("x client OpenSSL CBC SHA384 data\n")
	if _, err := conn.Write(message); err != nil {
		t.Fatal(err)
	}
	received := make(chan error, 1)
	go func() {
		read := make([]byte, len(message))
		_, err := io.ReadFull(stdout, read)
		if err == nil && !bytes.Equal(read, message) {
			err = errors.New("OpenSSL decrypted different application data")
		}
		received <- err
	}()
	select {
	case err := <-received:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	serverData := make([]byte, len(serverMessage))
	if _, err := io.ReadFull(conn, serverData); err != nil || !bytes.Equal(serverData, serverMessage) {
		t.Fatalf("OpenSSL encrypted server data failed: %v", err)
	}
}
