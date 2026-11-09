package trust

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type issuedCertificate struct {
	tls  tls.Certificate
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func issue(t *testing.T, change func(*x509.Certificate), parent *issuedCertificate) issuedCertificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "VPN test certificate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"vpn.test"},
	}
	if change != nil {
		change(template)
	}
	issuer, issuerKey := template, key
	if parent != nil {
		issuer, issuerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return issuedCertificate{tls: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}, cert: cert, key: key}
}

func certificateServer(t *testing.T, certificate tls.Certificate) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	requests := &atomic.Int32{}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		io.WriteString(w, "VPN endpoint")
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, requests
}

func baseConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "vpn.test"}
}

func performGET(t *testing.T, address string, config *tls.Config) error {
	t.Helper()
	transport := &http.Transport{TLSClientConfig: config, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	resp, err := client.Get(address)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, err = io.Copy(io.Discard, resp.Body)
	return err
}

func TestNormalVerificationDoesNotPrompt(t *testing.T) {
	certificate := issue(t, nil, nil)
	server, requests := certificateServer(t, certificate.tls)
	config := baseConfig()
	config.RootCAs = x509.NewCertPool()
	config.RootCAs.AddCert(certificate.cert)
	peerChecks, connectionChecks := 0, 0
	config.VerifyPeerCertificate = func(raw [][]byte, chains [][]*x509.Certificate) error {
		peerChecks++
		if len(raw) != 1 || len(chains) != 1 {
			t.Error("caller policy did not receive verified certificate chain")
		}
		return nil
	}
	config.VerifyConnection = func(state tls.ConnectionState) error {
		connectionChecks++
		if len(state.VerifiedChains) != 1 {
			t.Error("caller policy did not receive VerifiedChains")
		}
		return nil
	}
	verified, err := Build(context.Background(), server.URL, config, nil, func(CertificateInfo) (Decision, error) {
		t.Fatal("a trusted certificate prompted for approval")
		return Reject, nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 0 {
		t.Fatal("TLS preflight sent an HTTP request")
	}
	if err := performGET(t, server.URL, verified); err != nil {
		t.Fatal(err)
	}
	if peerChecks != 2 || connectionChecks != 2 || requests.Load() != 1 {
		t.Fatalf("peer=%d connection=%d requests=%d", peerChecks, connectionChecks, requests.Load())
	}
	if config.InsecureSkipVerify {
		t.Fatal("Build modified the supplied base configuration")
	}
}

func TestUnknownCertificateRejectsByDefault(t *testing.T) {
	certificate := issue(t, nil, nil)
	server, requests := certificateServer(t, certificate.tls)
	for _, choose := range []func(CertificateInfo) (Decision, error){
		nil,
		func(CertificateInfo) (Decision, error) { return Reject, nil },
		func(CertificateInfo) (Decision, error) { return Decision(99), nil },
	} {
		config, err := Build(context.Background(), server.URL, baseConfig(), nil, choose, nil)
		if config != nil || !errors.Is(err, ErrRejected) {
			t.Fatalf("default rejection returned config=%v, error=%v", config, err)
		}
	}
	if requests.Load() != 0 {
		t.Fatal("a rejected certificate received an HTTP request")
	}
}

func TestTrustOnceAndDisplayedHostnameMismatch(t *testing.T) {
	certificate := issue(t, func(c *x509.Certificate) { c.DNSNames = []string{"different-name.invalid"} }, nil)
	server, requests := certificateServer(t, certificate.tls)
	prompts := 0
	config, err := Build(context.Background(), server.URL, baseConfig(), nil, func(info CertificateInfo) (Decision, error) {
		prompts++
		if info.SHA256 != fingerprint(certificate.cert) || info.Subject != certificate.cert.Subject.String() || info.Issuer != certificate.cert.Issuer.String() || info.VerificationError == "" || !info.HostnameMismatch || info.ServerName != "vpn.test" || len(info.DNSNames) != 1 || info.NotAfter.IsZero() || info.NotBefore.IsZero() {
			t.Errorf("missing certificate details: %+v", info)
		}
		return TrustOnce, nil
	}, func(string, string) error {
		t.Error("TrustOnce persisted a pin")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 0 {
		t.Fatal("preflight sent HTTP data")
	}
	for range 2 {
		if err := performGET(t, server.URL, config); err != nil {
			t.Fatal(err)
		}
	}
	if prompts != 1 || requests.Load() != 2 {
		t.Fatalf("prompts=%d requests=%d", prompts, requests.Load())
	}
}

func TestTrustAlwaysPersistsOriginScopedPinAndReloadsWithoutPrompt(t *testing.T) {
	certificate := issue(t, nil, nil)
	server, _ := certificateServer(t, certificate.tls)
	saved := make(map[string][]string)
	writes := 0
	config, err := Build(context.Background(), server.URL, baseConfig(), nil, func(CertificateInfo) (Decision, error) {
		return TrustAlways, nil
	}, func(origin, pin string) error {
		writes++
		expected, _ := CanonicalOrigin(server.URL)
		if origin != expected || pin != fingerprint(certificate.cert) {
			t.Errorf("wrong saved pin: %s = %s", origin, pin)
		}
		saved[origin] = append(saved[origin], pin)
		return nil
	})
	if err != nil || writes != 1 {
		t.Fatalf("Build error=%v writes=%d", err, writes)
	}
	if err := performGET(t, server.URL, config); err != nil {
		t.Fatal(err)
	}
	reloaded, err := Build(context.Background(), server.URL, baseConfig(), saved, func(CertificateInfo) (Decision, error) {
		t.Fatal("saved matching pin prompted again")
		return Reject, nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := performGET(t, server.URL, reloaded); err != nil {
		t.Fatal(err)
	}

	// Another gateway serving the identical certificate must not inherit trust.
	otherServer, _ := certificateServer(t, certificate.tls)
	if _, err := Build(context.Background(), otherServer.URL, baseConfig(), saved, nil, nil); !errors.Is(err, ErrRejected) {
		t.Fatalf("pin leaked to a different gateway port: %v", err)
	}
}

func TestTrustAlwaysRequiresSuccessfulPersistence(t *testing.T) {
	certificate := issue(t, nil, nil)
	server, _ := certificateServer(t, certificate.tls)
	writeErr := errors.New("read-only configuration")
	choose := func(CertificateInfo) (Decision, error) { return TrustAlways, nil }
	if config, err := Build(context.Background(), server.URL, baseConfig(), nil, choose, nil); err == nil || config != nil {
		t.Fatal("accepted persistent trust without a configuration writer")
	}
	if config, err := Build(context.Background(), server.URL, baseConfig(), nil, choose, func(string, string) error { return writeErr }); !errors.Is(err, writeErr) || config != nil {
		t.Fatalf("persistence failure returned config=%v error=%v", config, err)
	}
}

func TestInvalidCertificatesNeverPromptOrUseStoredPins(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*x509.Certificate)
	}{
		{"expired", func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Minute) }},
		{"not yet valid", func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Minute) }},
		{"wrong extended key usage", func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			certificate := issue(t, test.change, nil)
			server, _ := certificateServer(t, certificate.tls)
			stored := map[string][]string{server.URL: {fingerprint(certificate.cert)}}
			config, err := Build(context.Background(), server.URL, baseConfig(), stored, func(CertificateInfo) (Decision, error) {
				t.Error("invalid certificate prompted for trust")
				return TrustAlways, nil
			}, func(string, string) error {
				t.Error("invalid certificate was persisted")
				return nil
			})
			if err == nil || config != nil {
				t.Fatal("accepted an invalid pinned certificate")
			}
		})
	}
}

func TestUnknownAuthorityWithoutSelfSignedRootDoesNotPrompt(t *testing.T) {
	root := issue(t, func(c *x509.Certificate) {
		c.IsCA = true
		c.Subject.CommonName = "Test private CA"
		c.KeyUsage |= x509.KeyUsageCertSign
	}, nil)
	leaf := issue(t, nil, &root)
	server, _ := certificateServer(t, leaf.tls)
	if _, err := Build(context.Background(), server.URL, baseConfig(), nil, func(CertificateInfo) (Decision, error) {
		t.Error("unknown issuer without a presented self-signed root prompted")
		return TrustOnce, nil
	}, nil); err == nil {
		t.Fatal("unknown root accepted")
	}
	// A cryptographically valid private CA chain with its self-signed root
	// presented qualifies for explicit approval of this leaf only.
	leaf.tls.Certificate = append(leaf.tls.Certificate, root.cert.Raw)
	chainServer, _ := certificateServer(t, leaf.tls)
	config, err := Build(context.Background(), chainServer.URL, baseConfig(), nil, func(CertificateInfo) (Decision, error) {
		return TrustOnce, nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := performGET(t, chainServer.URL, config); err != nil {
		t.Fatal(err)
	}
}

func TestWrongSelfSignatureDoesNotPrompt(t *testing.T) {
	certificate := issue(t, nil, nil)
	raw := append([]byte(nil), certificate.cert.Raw...)
	raw[len(raw)-1] ^= 1
	certificate.tls.Certificate = [][]byte{raw}
	server, _ := certificateServer(t, certificate.tls)
	if _, err := Build(context.Background(), server.URL, baseConfig(), nil, func(CertificateInfo) (Decision, error) {
		t.Error("a certificate with an invalid self-signature prompted")
		return TrustOnce, nil
	}, nil); err == nil {
		t.Fatal("invalid self-signature accepted")
	}
}

func TestCertificateChangeRequiresNewStartupApproval(t *testing.T) {
	first, second := issue(t, nil, nil), issue(t, nil, nil)
	current := &atomic.Pointer[tls.Certificate]{}
	current.Store(&first.tls)
	requests := &atomic.Int32{}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		io.WriteString(w, "VPN")
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return current.Load(), nil }}
	server.StartTLS()
	defer server.Close()
	prompts := 0
	config, err := Build(context.Background(), server.URL, baseConfig(), nil, func(CertificateInfo) (Decision, error) {
		prompts++
		return TrustOnce, nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := performGET(t, server.URL, config); err != nil {
		t.Fatal(err)
	}
	current.Store(&second.tls)
	if err := performGET(t, server.URL, config); !errors.Is(err, ErrCertificateChanged) {
		t.Fatalf("changed certificate returned %v", err)
	}
	if prompts != 1 || requests.Load() != 1 {
		t.Fatalf("runtime handshake prompted or sent HTTP: prompts=%d requests=%d", prompts, requests.Load())
	}
	saved := map[string][]string{server.URL: {fingerprint(first.cert)}}
	_, err = Build(context.Background(), server.URL, baseConfig(), saved, func(info CertificateInfo) (Decision, error) {
		prompts++
		if info.SHA256 != fingerprint(second.cert) {
			t.Error("changed certificate fingerprint missing from prompt")
		}
		return Reject, nil
	}, nil)
	if !errors.Is(err, ErrRejected) || prompts != 2 {
		t.Fatalf("new startup did not request approval: error=%v prompts=%d", err, prompts)
	}
}

func TestCallerPolicyFailureDoesNotPersistPin(t *testing.T) {
	certificate := issue(t, nil, nil)
	server, _ := certificateServer(t, certificate.tls)
	policyErr := errors.New("additional policy rejected certificate")
	base := baseConfig()
	base.VerifyConnection = func(tls.ConnectionState) error { return policyErr }
	if config, err := Build(context.Background(), server.URL, base, nil, func(CertificateInfo) (Decision, error) {
		return TrustAlways, nil
	}, func(string, string) error {
		t.Error("pin persisted before policy or handshake completed")
		return nil
	}); !errors.Is(err, policyErr) || config != nil {
		t.Fatalf("policy rejection returned config=%v error=%v", config, err)
	}
}

func TestCancelDuringCertificateReviewDoesNotPersist(t *testing.T) {
	certificate := issue(t, nil, nil)
	server, requests := certificateServer(t, certificate.tls)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err := Build(ctx, server.URL, baseConfig(), nil, func(CertificateInfo) (Decision, error) {
		cancel()
		return TrustAlways, nil
	}, func(string, string) error {
		t.Error("canceled review persisted a pin")
		return nil
	})
	if !errors.Is(err, context.Canceled) || requests.Load() != 0 {
		t.Fatalf("cancel during review: error=%v HTTP requests=%d", err, requests.Load())
	}
}

func TestCertificateChangedDuringReviewDoesNotPersist(t *testing.T) {
	first, second := issue(t, nil, nil), issue(t, nil, nil)
	current := &atomic.Pointer[tls.Certificate]{}
	current.Store(&first.tls)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("certificate review sent an HTTP request")
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return current.Load(), nil }}
	server.StartTLS()
	defer server.Close()
	_, err := Build(context.Background(), server.URL, baseConfig(), nil, func(CertificateInfo) (Decision, error) {
		current.Store(&second.tls)
		return TrustAlways, nil
	}, func(string, string) error {
		t.Error("certificate changed before completing TLS but pin was persisted")
		return nil
	})
	if !errors.Is(err, ErrCertificateChanged) {
		t.Fatalf("certificate changed during review: %v", err)
	}
}

func TestCanonicalOriginAndPinValidation(t *testing.T) {
	for input, want := range map[string]string{
		"https://VPN.Example.com":      "https://vpn.example.com:443",
		"https://VPN.Example.com:443/": "https://vpn.example.com:443",
		"https://[2001:db8::1]:8443":   "https://[2001:db8::1]:8443",
		"https://192.0.2.1:00443":      "https://192.0.2.1:443",
	} {
		if got, err := CanonicalOrigin(input); err != nil || got != want {
			t.Errorf("CanonicalOrigin(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	for _, bad := range []string{"http://vpn.test", "https://vpn.test/path", "https://user:pass@vpn.test", "https://vpn.test?token=x", "https://vpn.test:0", "https://vpn.test:65536"} {
		if _, err := CanonicalOrigin(bad); err == nil {
			t.Errorf("accepted invalid origin %q", bad)
		}
	}
	if _, err := pinsForOrigin(map[string][]string{"https://vpn.test": {"bad pin"}}, "https://vpn.test:443"); err == nil {
		t.Error("invalid fingerprint accepted")
	}
	if _, err := pinsForOrigin(map[string][]string{"http://vpn.test": {strings.Repeat("a", 64)}}, "https://vpn.test:443"); err == nil {
		t.Error("invalid pin origin accepted")
	}
	pins, err := pinsForOrigin(map[string][]string{"https://VPN.test": {strings.Repeat("AB:", 31) + "AB"}}, "https://vpn.test:443")
	if _, ok := pins[strings.Repeat("ab", 32)]; err != nil || !ok {
		t.Error("normalized colon-delimited fingerprint missing")
	}
}

func TestBuildRejectsInsecureBaseAndPropagatesPromptFailure(t *testing.T) {
	base := baseConfig()
	base.InsecureSkipVerify = true
	if _, err := Build(context.Background(), "https://127.0.0.1:1", base, nil, nil, nil); err == nil {
		t.Error("insecure_skip_verify was accepted")
	}
	certificate := issue(t, nil, nil)
	server, _ := certificateServer(t, certificate.tls)
	inputErr := errors.New("interactive input unavailable")
	if _, err := Build(context.Background(), server.URL, baseConfig(), nil, func(CertificateInfo) (Decision, error) {
		return Reject, inputErr
	}, nil); !errors.Is(err, inputErr) {
		t.Fatalf("prompt error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Build(ctx, server.URL, baseConfig(), nil, nil, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context returned %v", err)
	}
}
