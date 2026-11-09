// Package dtlstransport implements Ruijie's authenticated DTLS 1.2 transport.
package dtlstransport

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1" // Required by the native protocol's HMAC cookie, not certificate signatures.
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
)

// cookieHook reproduces the native info callback FUN_1800b6ea0:
// HMAC-SHA1(secret16, HelloVerifyRequest.cookie), replacing the cookie only
// when its original length equals the 20-byte SHA-1 output. The initial empty
// ClientHello cookie and cookies with other lengths are left unchanged.
func cookieHook(secret []byte) func(handshake.MessageClientHello) handshake.Message {
	key := bytes.Clone(secret)
	return func(hello handshake.MessageClientHello) handshake.Message {
		if len(hello.Cookie) == sha1.Size {
			mac := hmac.New(sha1.New, key)
			_, _ = mac.Write(hello.Cookie)
			hello.Cookie = mac.Sum(nil)
		}
		return &hello
	}
}

// Dial completes a DTLS 1.2 handshake to the gateway's negotiated UDP endpoint.
// The context controls dialing and handshaking; the caller owns the returned
// connection after success. DTLS 1.0 requires a separate implementation.
//
// tlsConfig supplies ServerName, RootCAs, client Certificates, CipherSuites,
// NextProtos, KeyLogWriter, and both certificate verification callbacks.
// Its TLS version bounds must permit TLS 1.2 (the DTLS 1.2 equivalent).
func Dial(ctx context.Context, endpoint netip.AddrPort, secret []byte, tlsConfig *tls.Config) (net.Conn, error) {
	if !endpoint.IsValid() || endpoint.Port() == 0 || endpoint.Addr().IsUnspecified() || endpoint.Addr().IsMulticast() {
		return nil, errors.New("DTLS requires a valid unicast gateway IP and UDP port")
	}
	if len(secret) != 16 {
		return nil, errors.New("DTLS cookie secret must contain exactly 16 bytes")
	}
	if tlsConfig == nil {
		return nil, errors.New("DTLS certificate configuration is required")
	}
	if tlsConfig.MinVersion > tls.VersionTLS12 || (tlsConfig.MaxVersion != 0 && tlsConfig.MaxVersion < tls.VersionTLS12) {
		return nil, errors.New("TLS version policy does not permit DTLS 1.2")
	}
	if tlsConfig.GetClientCertificate != nil {
		// Pion's callback does not expose the server's signature schemes, so
		// silently adapting this TLS callback would change certificate policy.
		return nil, errors.New("DTLS requires static client certificates; GetClientCertificate is unsupported")
	}
	config := tlsConfig.Clone()
	if config.ServerName == "" {
		config.ServerName = endpoint.Addr().String()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// The pinned Config API can express an explicitly empty built-in suite
	// list when the caller permits only our custom suite. Functional options
	// reject that list; adding implicit suites would change the caller's policy.
	pc := &dtls.Config{
		ServerName:             config.ServerName,
		RootCAs:                config.RootCAs,
		InsecureSkipVerify:     config.InsecureSkipVerify,
		ClientHelloMessageHook: cookieHook(secret),
		Certificates:           config.Certificates,
		SupportedProtocols:     config.NextProtos,
		KeyLogWriter:           config.KeyLogWriter,
		// Matches the native SSL_set_mtu(1472) setting.
		MTU: 1472,
	}
	pc.CustomCipherSuites = gatewayCipherSuites
	if len(config.CipherSuites) > 0 {
		pc.CustomCipherSuites = nil
		pc.CipherSuites = make([]dtls.CipherSuiteID, 0, len(config.CipherSuites))
		for _, id := range config.CipherSuites {
			if dtls.CipherSuiteID(id) == gatewayCipherSuiteID {
				pc.CustomCipherSuites = gatewayCipherSuites
			} else {
				pc.CipherSuites = append(pc.CipherSuites, dtls.CipherSuiteID(id))
			}
		}
	}
	// Pion keeps DER peer certificates in State rather than tls.ConnectionState.
	// Preserve the actual verified chains supplied by Pion for TLS callbacks.
	var verifiedChains [][]*x509.Certificate
	if config.VerifyPeerCertificate != nil || config.VerifyConnection != nil {
		pc.VerifyPeerCertificate = func(raw [][]byte, chains [][]*x509.Certificate) error {
			verifiedChains = chains
			if config.VerifyPeerCertificate != nil {
				return config.VerifyPeerCertificate(raw, chains)
			}
			return nil
		}
	}
	if config.VerifyConnection != nil {
		pc.VerifyConnection = func(state *dtls.State) error {
			cs := tls.ConnectionState{
				Version:                    tls.VersionTLS12,
				HandshakeComplete:          true,
				CipherSuite:                uint16(state.CipherSuiteID),
				ServerName:                 config.ServerName,
				NegotiatedProtocol:         state.NegotiatedProtocol,
				NegotiatedProtocolIsMutual: state.NegotiatedProtocol != "",
				VerifiedChains:             verifiedChains,
			}
			for _, raw := range state.PeerCertificates {
				cert, err := x509.ParseCertificate(raw)
				if err != nil {
					return err
				}
				cs.PeerCertificates = append(cs.PeerCertificates, cert)
			}
			return config.VerifyConnection(cs)
		}
	}
	network, bind := "udp4", "0.0.0.0:0"
	if endpoint.Addr().Is6() {
		network, bind = "udp6", "[::]:0"
	}
	var listenConfig net.ListenConfig
	packet, err := listenConfig.ListenPacket(ctx, network, bind)
	if err != nil {
		return nil, fmt.Errorf("open DTLS UDP socket: %w", err)
	}
	conn, err := dtls.Client(packet, net.UDPAddrFromAddrPort(endpoint), pc)
	if err != nil {
		_ = packet.Close()
		return nil, fmt.Errorf("configure DTLS 1.2: %w", err)
	}
	if err = conn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		_ = packet.Close()
		return nil, fmt.Errorf("DTLS 1.2 handshake: %w", err)
	}
	return conn, nil
}
