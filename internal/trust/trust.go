// Package trust implements explicit, origin-scoped trust for self-signed VPN
// certificates. Normal certificate verification remains the default.
package trust

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Decision is an explicit answer to a certificate trust prompt. The zero value
// rejects the certificate.
type Decision uint8

const (
	Reject Decision = iota
	TrustOnce
	TrustAlways
)

var (
	// ErrRejected indicates an unknown self-signed certificate was not approved.
	ErrRejected = errors.New("VPN certificate trust was rejected")
	// ErrCertificateChanged is returned if an unapproved certificate appears
	// after the startup preflight. Restarting performs a new interactive check.
	ErrCertificateChanged = errors.New("VPN certificate changed after startup; restart to review it")
	errNeedsApproval      = errors.New("VPN certificate requires an explicit trust decision")
)

// CertificateInfo contains only public certificate metadata. Display string
// fields with quoting or escaping: certificate subjects are untrusted text.
type CertificateInfo struct {
	Origin            string
	ServerName        string
	Subject           string
	Issuer            string
	SHA256            string
	DNSNames          []string
	IPAddresses       []string
	NotBefore         time.Time
	NotAfter          time.Time
	HostnameMismatch  bool
	VerificationError string
}

// CanonicalOrigin returns an HTTPS origin with a lower-case host and explicit
// port, so trust for one gateway cannot extend to another host or port.
func CanonicalOrigin(server string) (string, error) {
	u, err := url.Parse(server)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || strings.ContainsAny(server, "\r\n") {
		return "", errors.New("certificate trust requires an HTTPS origin")
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	parsedPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil || parsedPort == 0 {
		return "", errors.New("certificate trust requires a valid gateway port")
	}
	host := strings.ToLower(u.Hostname())
	return "https://" + net.JoinHostPort(host, strconv.Itoa(int(parsedPort))), nil
}

// Build performs a TLS-only preflight before any login credentials are sent.
// It prompts only for otherwise-valid chains leading to a cryptographically
// self-signed certificate presented by this gateway. An explicitly approved
// leaf may also have a hostname mismatch, shown in CertificateInfo. Expired,
// not-yet-valid, wrongly signed or otherwise invalid chains remain rejected.
//
// storedPins maps HTTPS origins to leaf certificate SHA-256 fingerprints.
// choose may be nil, in which case unknown self-signed certificates are rejected.
// TrustAlways requires a successful persist(origin, fingerprint) call, made only
// after the complete preflight handshake succeeds. TrustOnce lasts for the
// returned TLS config's lifetime. No callbacks prompt during subsequent HTTP
// handshakes, and changed untrusted certificates are rejected until restart.
// Each network handshake has a 30-second timeout. Interactive choice takes place
// between handshakes, so time spent reviewing a certificate does not consume
// the network timeout; the caller's ctx must remain live throughout.
//
// The returned config uses VerifyConnection to perform mandatory verification;
// its internal InsecureSkipVerify flag only disables Go's duplicate automatic
// verifier. A base config explicitly disabling verification is refused.
func Build(ctx context.Context, server string, base *tls.Config, storedPins map[string][]string, choose func(CertificateInfo) (Decision, error), persist func(origin, fingerprint string) error) (*tls.Config, error) {
	origin, err := CanonicalOrigin(server)
	if err != nil {
		return nil, err
	}
	if base == nil {
		base = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	if base.InsecureSkipVerify {
		return nil, errors.New("interactive certificate trust cannot use insecure_skip_verify")
	}
	u, _ := url.Parse(origin)
	config := base.Clone()
	if config.ServerName == "" {
		config.ServerName = u.Hostname()
	}
	pins, err := pinsForOrigin(storedPins, origin)
	if err != nil {
		return nil, err
	}

	var approved string
	var always string
	var pending CertificateInfo
	verify := func(state tls.ConnectionState, collect bool) error {
		if len(state.PeerCertificates) == 0 {
			return errors.New("VPN server did not present a certificate")
		}
		leaf := state.PeerCertificates[0]
		options := verifyOptions(config, state.PeerCertificates)
		chains, verificationErr := leaf.Verify(options)
		if verificationErr != nil {
			// A self-signed root alone is insufficient: rebuilding the whole
			// chain with that root must succeed, including time, EKU, path
			// constraints, signatures and critical extension validation.
			var validSelfSigned bool
			chains, validSelfSigned = selfSignedChains(leaf, options, state.PeerCertificates)
			if !validSelfSigned {
				return fmt.Errorf("verify VPN certificate: %w", verificationErr)
			}
			fingerprint := fingerprint(leaf)
			_, stored := pins[fingerprint]
			if !stored && fingerprint != approved {
				if collect {
					pending = certificateInfo(origin, config.ServerName, leaf, verificationErr)
					return errNeedsApproval
				}
				return fmt.Errorf("%w (SHA-256 %s)", ErrCertificateChanged, fingerprint)
			}
		}
		// Retain any stricter caller-supplied policy, supplying the chains
		// produced by this verifier instead of nil VerifiedChains.
		if base.VerifyPeerCertificate != nil {
			raw := make([][]byte, len(state.PeerCertificates))
			for i, cert := range state.PeerCertificates {
				raw[i] = cert.Raw
			}
			if err := base.VerifyPeerCertificate(raw, chains); err != nil {
				return err
			}
		}
		if base.VerifyConnection != nil {
			state.VerifiedChains = chains
			return base.VerifyConnection(state)
		}
		return nil
	}
	config.InsecureSkipVerify = true // Mandatory verification is in VerifyConnection below.
	config.VerifyPeerCertificate = nil
	config.VerifyConnection = func(state tls.ConnectionState) error { return verify(state, false) }
	probe := config.Clone()
	probe.ClientSessionCache = nil // Always inspect the certificate in a fresh startup handshake.
	probe.VerifyConnection = func(state tls.ConnectionState) error { return verify(state, true) }
	err = preflight(ctx, u.Host, probe)
	if errors.Is(err, errNeedsApproval) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if choose == nil {
			return nil, fmt.Errorf("%w (SHA-256 %s)", ErrRejected, pending.SHA256)
		}
		decision, choiceErr := choose(pending)
		if choiceErr != nil {
			return nil, fmt.Errorf("choose VPN certificate trust: %w", choiceErr)
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		switch decision {
		case TrustOnce:
			approved = pending.SHA256
		case TrustAlways:
			if persist == nil {
				return nil, errors.New("persistent certificate trust requires a configuration writer")
			}
			approved, always = pending.SHA256, pending.SHA256
		default:
			return nil, fmt.Errorf("%w (SHA-256 %s)", ErrRejected, pending.SHA256)
		}
		// The first handshake intentionally stopped at the trust boundary.
		// Reconnect with the exact approved leaf to prove possession of its
		// key and complete TLS before persisting or sending credentials.
		probe.VerifyConnection = config.VerifyConnection
		err = preflight(ctx, u.Host, probe)
	}
	if err != nil {
		return nil, fmt.Errorf("VPN TLS preflight: %w", err)
	}
	if always != "" {
		if err := persist(origin, always); err != nil {
			return nil, fmt.Errorf("save VPN certificate trust: %w", err)
		}
	}
	return config, nil
}

func preflight(ctx context.Context, address string, config *tls.Config) error {
	probeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	dialer := tls.Dialer{NetDialer: &net.Dialer{}, Config: config}
	conn, err := dialer.DialContext(probeCtx, "tcp", address)
	if err != nil {
		return err
	}
	return conn.Close()
}

func pinsForOrigin(stored map[string][]string, origin string) (map[string]struct{}, error) {
	pins := make(map[string]struct{})
	for gateway, values := range stored {
		canonical, err := CanonicalOrigin(gateway)
		if err != nil {
			return nil, errors.New("trusted_certificates contains an invalid HTTPS origin")
		}
		for _, value := range values {
			value = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), ":", ""))
			raw, err := hex.DecodeString(value)
			if err != nil || len(raw) != sha256.Size {
				return nil, errors.New("trusted_certificates contains an invalid SHA-256 fingerprint")
			}
			if canonical == origin {
				pins[value] = struct{}{}
			}
		}
	}
	return pins, nil
}

func verifyOptions(config *tls.Config, peers []*x509.Certificate) x509.VerifyOptions {
	intermediates := x509.NewCertPool()
	for _, cert := range peers[1:] {
		intermediates.AddCert(cert)
	}
	options := x509.VerifyOptions{
		DNSName:       config.ServerName,
		Roots:         config.RootCAs,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if config.Time != nil {
		options.CurrentTime = config.Time()
	}
	return options
}

func selfSignedChains(leaf *x509.Certificate, options x509.VerifyOptions, peers []*x509.Certificate) ([][]*x509.Certificate, bool) {
	for _, cert := range peers {
		if !bytes.Equal(cert.RawSubject, cert.RawIssuer) {
			continue
		}
		if err := cert.CheckSignatureFrom(cert); err != nil {
			// Self-signed end-entity certificates need not be CAs. Allow
			// this case only for the exact leaf, and verify its self-signature
			// directly; it cannot serve as a root for a different leaf.
			if !bytes.Equal(cert.Raw, leaf.Raw) || cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) != nil {
				continue
			}
		}
		roots := x509.NewCertPool()
		roots.AddCert(cert)
		options.Roots = roots
		options.DNSName = "" // Explicit leaf trust can approve a displayed hostname mismatch.
		if chains, err := leaf.Verify(options); err == nil {
			return chains, true
		}
	}
	return nil, false
}

func fingerprint(cert *x509.Certificate) string {
	digest := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(digest[:])
}

func certificateInfo(origin, serverName string, cert *x509.Certificate, verificationErr error) CertificateInfo {
	info := CertificateInfo{
		Origin:            origin,
		ServerName:        serverName,
		Subject:           cert.Subject.String(),
		Issuer:            cert.Issuer.String(),
		SHA256:            fingerprint(cert),
		DNSNames:          append([]string(nil), cert.DNSNames...),
		NotBefore:         cert.NotBefore,
		NotAfter:          cert.NotAfter,
		HostnameMismatch:  cert.VerifyHostname(serverName) != nil,
		VerificationError: verificationErr.Error(),
	}
	for _, ip := range cert.IPAddresses {
		info.IPAddresses = append(info.IPAddresses, ip.String())
	}
	return info
}
