package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

const minimalConfig = `vpn:
  server: https://gateway.test:443
  username: unit-test-user
  password: "unit-test-only: # secret"
`

func writeConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadDefaultsAndRelativeCAPath(t *testing.T) {
	path := writeConfig(t, minimalConfig+`  tls:
    ca_file: certificates/gateway.pem
    server_name: gateway.test
    trusted_certificates:
      "https://gateway.test:443": ["`+strings.Repeat("a", 64)+`"]
`)
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.VPN.Username != "unit-test-user" || c.VPN.Password != "unit-test-only: # secret" {
		t.Fatal("credential values were changed while parsing YAML")
	}
	if c.SOCKS5.Listen != "127.0.0.1:1080" || c.SOCKS5.MaxConnections != 128 || c.Timeouts.Connect != 20*time.Second || c.Timeouts.Handshake != 30*time.Second {
		t.Fatal("missing defaults for SOCKS listener or network timeouts")
	}
	if c.VPN.TLS.CAFile != filepath.Join(filepath.Dir(path), "certificates", "gateway.pem") || c.VPN.TLS.ServerName != "gateway.test" {
		t.Fatal("CA path was not resolved relative to the configuration file")
	}
	if !reflect.DeepEqual(c.VPN.TLS.TrustedCertificates["https://gateway.test:443"], []string{strings.Repeat("a", 64)}) {
		t.Fatal("certificate pins were not loaded")
	}
}

func TestLoadStrictYAML(t *testing.T) {
	for _, test := range []struct{ name, content string }{
		{"empty file", ""},
		{"unknown root field", minimalConfig + "unexpected: true\n"},
		{"unknown VPN field", minimalConfig + "  unknown_option: true\n"},
		{"unknown TLS field", minimalConfig + "  tls:\n    skip_verification_typo: true\n"},
		{"unknown SOCKS field", minimalConfig + "socks5:\n  listing: 127.0.0.1:1080\n"},
		{"unknown timeout field", minimalConfig + "timeouts:\n  connection: 3s\n"},
		{"duplicate key", minimalConfig + "  username: duplicate\n"},
		{"second document", minimalConfig + "---\nvpn: {}\n"},
		{"second empty document", minimalConfig + "---\n"},
		{"non mapping root", "[1, 2, 3]\n"},
		{"invalid duration", minimalConfig + "timeouts:\n  connect: sometimes\n"},
		{"invalid YAML", "vpn: [\n"},
		{"oversized file", minimalConfig + "#" + strings.Repeat(" ", 1<<20) + "\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Load(writeConfig(t, test.content)); err == nil {
				t.Fatal("invalid or ambiguous YAML was accepted")
			}
		})
	}
}

func TestLoadEnvironmentPassword(t *testing.T) {
	const name = "RGSSLVPN_UNIT_TEST_PASSWORD"
	t.Setenv(name, "environment-only-test-secret")
	contents := strings.Replace(minimalConfig, "  password: \"unit-test-only: # secret\"\n", "  password_env: "+name+"\n", 1)
	c, err := Load(writeConfig(t, contents))
	if err != nil {
		t.Fatal(err)
	}
	if c.VPN.Password != "environment-only-test-secret" || c.VPN.PasswordEnv != name {
		t.Fatal("password environment variable was not resolved")
	}
	for _, invalid := range []string{
		minimalConfig + "  password_env: " + name + "\n",
		strings.Replace(contents, name, "RGSSLVPN_MISSING_"+filepath.Base(t.TempDir()), 1),
	} {
		if _, err := Load(writeConfig(t, invalid)); err == nil {
			t.Error("ambiguous or missing environment credentials were accepted")
		} else if strings.Contains(err.Error(), "environment-only-test-secret") {
			t.Error("configuration error exposed a resolved environment password")
		}
	}
	t.Setenv(name, "")
	if _, err := Load(writeConfig(t, contents)); err == nil {
		t.Error("empty environment password was accepted")
	}
}

func TestValidateConnectionAndListener(t *testing.T) {
	valid, err := Load(writeConfig(t, minimalConfig))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		change func(*Config)
	}{
		{"HTTP server", func(c *Config) { c.VPN.Server = "http://gateway.test" }},
		{"server credentials", func(c *Config) { c.VPN.Server = "https://user:password@gateway.test" }},
		{"server path", func(c *Config) { c.VPN.Server = "https://gateway.test/private" }},
		{"server query", func(c *Config) { c.VPN.Server = "https://gateway.test?token=private" }},
		{"server fragment", func(c *Config) { c.VPN.Server = "https://gateway.test/#private" }},
		{"server newline", func(c *Config) { c.VPN.Server = "https://gateway.test\n" }},
		{"server port overflow", func(c *Config) { c.VPN.Server = "https://gateway.test:65536" }},
		{"server port zero", func(c *Config) { c.VPN.Server = "https://gateway.test:0" }},
		{"missing username", func(c *Config) { c.VPN.Username = "" }},
		{"missing password", func(c *Config) { c.VPN.Password = "" }},
		{"example username", func(c *Config) { c.VPN.Username = "your-username" }},
		{"example password", func(c *Config) { c.VPN.Password = "your-password" }},
		{"example server", func(c *Config) { c.VPN.Server = "https://vpn.example.com:443" }},
		{"insecure TLS", func(c *Config) { c.VPN.TLS.InsecureSkipVerify = true }},
		{"missing listener port", func(c *Config) { c.SOCKS5.Listen = "127.0.0.1" }},
		{"listener port zero", func(c *Config) { c.SOCKS5.Listen = "127.0.0.1:0" }},
		{"listener port overflow", func(c *Config) { c.SOCKS5.Listen = "127.0.0.1:65536" }},
		{"listener service name", func(c *Config) { c.SOCKS5.Listen = "127.0.0.1:http" }},
		{"listener hostname", func(c *Config) { c.SOCKS5.Listen = "localhost:1080" }},
		{"public unauthenticated listener", func(c *Config) { c.SOCKS5.Listen = "0.0.0.0:1080" }},
		{"SOCKS username only", func(c *Config) { c.SOCKS5.Username = "alice" }},
		{"SOCKS password only", func(c *Config) { c.SOCKS5.Password = "password" }},
		{"SOCKS overlong credential", func(c *Config) { c.SOCKS5.Username = strings.Repeat("u", 256); c.SOCKS5.Password = "password" }},
		{"zero connection limit", func(c *Config) { c.SOCKS5.MaxConnections = 0 }},
		{"excessive connection limit", func(c *Config) { c.SOCKS5.MaxConnections = 65537 }},
		{"zero connect timeout", func(c *Config) { c.Timeouts.Connect = 0 }},
		{"negative handshake timeout", func(c *Config) { c.Timeouts.Handshake = -time.Second }},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := valid
			test.change(&c)
			if err := c.Validate(); err == nil {
				t.Fatal("invalid connection configuration was accepted")
			}
		})
	}
	for _, listen := range []string{"127.0.0.1:1080", "[::1]:1080", "0.0.0.0:1080"} {
		c := valid
		c.SOCKS5.Listen = listen
		c.SOCKS5.Username, c.SOCKS5.Password = "unit-user", "unit-password"
		if err := c.Validate(); err != nil {
			t.Errorf("valid authenticated listener %s: %v", listen, err)
		}
	}
}

func TestTLSBuildLoadsCustomCA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Unit test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:        true, BasicConstraintsValid: true, DNSNames: []string{"gateway.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	config, err := (TLS{CAFile: path, ServerName: "gateway.test"}).Build()
	if err != nil {
		t.Fatal(err)
	}
	if config.InsecureSkipVerify || config.MinVersion != tls.VersionTLS12 || config.ServerName != "gateway.test" {
		t.Fatal("TLS verification settings are incorrect")
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: config.RootCAs, DNSName: "gateway.test"}); err != nil {
		t.Fatalf("custom CA was not trusted: %v", err)
	}
	if err := os.WriteFile(path, []byte("not a certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := (TLS{CAFile: path}).Build(); err == nil {
		t.Error("invalid CA file was accepted")
	}
	if _, err := (TLS{CAFile: path + ".missing"}).Build(); err == nil {
		t.Error("missing CA file was accepted")
	}
}

func TestSaveTrustPreservesCredentialsCommentsAndOtherOrigins(t *testing.T) {
	const origin = "https://gateway.test:443"
	oldPin, newPin, otherPin := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	contents := `# operator's connection notes
vpn:
  server: https://gateway.test:443
  username: 'unit-test-user' # username note
  password: 'literal: # test-only value' # credential note
  password_env: ''
  tls: # TLS note
    ca_file: ''
    trusted_certificates: # pin notes
      'https://gateway.test:443': ['` + oldPin + `']
      'https://other.test:8443': ['` + otherPin + `'] # other gateway note
socks5:
  listen: 127.0.0.1:1080
  username: socks-unit-user
  password: 'another: # test-only value'
timeouts:
  connect: 20s
  handshake: 30s
`
	path := writeConfig(t, contents)
	if err := SaveTrust(path, origin, newPin); err != nil {
		t.Fatal(err)
	}
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, comment := range []string{"# operator's connection notes", "# username note", "# credential note", "# TLS note", "# pin notes", "# other gateway note"} {
		if !strings.Contains(string(saved), comment) {
			t.Errorf("lost YAML comment %q", comment)
		}
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.VPN.Username != "unit-test-user" || c.VPN.Password != "literal: # test-only value" || c.SOCKS5.Username != "socks-unit-user" || c.SOCKS5.Password != "another: # test-only value" {
		t.Fatal("saving certificate trust altered credentials")
	}
	if !reflect.DeepEqual(c.VPN.TLS.TrustedCertificates[origin], []string{newPin}) || !reflect.DeepEqual(c.VPN.TLS.TrustedCertificates["https://other.test:8443"], []string{otherPin}) {
		t.Fatal("saving trust failed to replace only the selected gateway pin")
	}
	leftovers, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".vpn-config-*"))
	if err != nil || len(leftovers) != 0 {
		t.Fatal("saving trust left temporary configuration files behind")
	}
	if runtime.GOOS != "windows" {
		stat, err := os.Stat(path)
		if err != nil || stat.Mode().Perm() != 0600 {
			t.Fatal("saved credentials do not have private file permissions")
		}
	}
}

func TestSaveTrustDoesNotMaterializeEnvironmentPassword(t *testing.T) {
	const name = "RGSSLVPN_UNIT_TEST_TRUST_PASSWORD"
	t.Setenv(name, "environment-secret-must-not-be-written")
	contents := strings.Replace(minimalConfig, "  password: \"unit-test-only: # secret\"\n", "  password_env: "+name+" # environment reference\n", 1)
	path := writeConfig(t, contents)
	if _, err := Load(path); err != nil {
		t.Fatal(err)
	}
	if err := SaveTrust(path, "https://gateway.test:443", strings.Repeat("d", 64)); err != nil {
		t.Fatal(err)
	}
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(saved), "environment-secret-must-not-be-written") || !strings.Contains(string(saved), name) || !strings.Contains(string(saved), "# environment reference") {
		t.Fatal("saving trust changed an environment password reference")
	}
}

func TestSaveTrustReplacesAllEquivalentOriginPins(t *testing.T) {
	oldPin, newPin := strings.Repeat("a", 64), strings.Repeat("b", 64)
	contents := minimalConfig + `  tls:
    trusted_certificates:
      "https://GATEWAY.test": ["` + oldPin + `"] # default-port alias
      "https://gateway.test:443/": ["` + oldPin + `"] # slash alias
      "https://gateway.test:443": ["` + oldPin + `"]
      "https://gateway.test:8443": ["` + oldPin + `"] # distinct gateway
`
	path := writeConfig(t, contents)
	if err := SaveTrust(path, "https://gateway.test:443", newPin); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, alias := range []string{"https://GATEWAY.test", "https://gateway.test:443/", "https://gateway.test:443"} {
		if !reflect.DeepEqual(c.VPN.TLS.TrustedCertificates[alias], []string{newPin}) {
			t.Errorf("equivalent origin %q retained a superseded pin", alias)
		}
	}
	if !reflect.DeepEqual(c.VPN.TLS.TrustedCertificates["https://gateway.test:8443"], []string{oldPin}) {
		t.Error("different gateway port had its pin replaced")
	}
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, comment := range []string{"# default-port alias", "# slash alias", "# distinct gateway"} {
		if !strings.Contains(string(saved), comment) {
			t.Errorf("lost origin comment %q", comment)
		}
	}
}

func TestSaveTrustPreservesUnrelatedYAMLNodes(t *testing.T) {
	// Persistence edits the document tree instead of marshaling Config: fields
	// added by another tool must not silently disappear during this operation.
	path := writeConfig(t, minimalConfig+"external_metadata:\n  label: 'operator: notes' # retain\n")
	if err := SaveTrust(path, "https://gateway.test:443", strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal(saved, &document); err != nil {
		t.Fatal(err)
	}
	metadata, ok := document["external_metadata"].(map[string]any)
	if !ok || metadata["label"] != "operator: notes" || !strings.Contains(string(saved), "# retain") {
		t.Fatal("saving trust deleted unrelated document nodes")
	}
}

func TestSaveTrustRefusesInvalidStructureWithoutChangingFile(t *testing.T) {
	const origin = "https://gateway.test:443"
	for _, test := range []struct{ name, content string }{
		{"invalid YAML", "vpn: [\n"},
		{"empty file", ""},
		{"non mapping document", "[1, 2, 3]\n"},
		{"non mapping VPN", "vpn: wrong\n"},
		{"non mapping TLS", "vpn:\n  tls: []\n"},
		{"non mapping pin table", "vpn:\n  tls:\n    trusted_certificates: wrong\n"},
		{"non sequence pins", "vpn:\n  tls:\n    trusted_certificates:\n      'https://gateway.test:443': wrong\n"},
		{"multiple documents", minimalConfig + "---\noperator_metadata: must not disappear\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := writeConfig(t, test.content)
			if err := SaveTrust(path, origin, strings.Repeat("a", 64)); err == nil {
				t.Error("invalid or ambiguous configuration was overwritten")
			}
			saved, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(saved) != test.content {
				t.Error("failed trust save changed the original document")
			}
			leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".vpn-config-*"))
			if len(leftovers) != 0 {
				t.Error("failed trust save left temporary files behind")
			}
		})
	}
}
