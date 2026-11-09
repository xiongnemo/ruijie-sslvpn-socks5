package config

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/xiongnemo/ruijie-sslvpn-socks5/internal/trust"
)

type Config struct {
	VPN      VPN      `yaml:"vpn"`
	SOCKS5   SOCKS5   `yaml:"socks5"`
	Timeouts Timeouts `yaml:"timeouts"`
}
type VPN struct {
	Server      string `yaml:"server"`
	Username    string `yaml:"username"`
	Password    string `yaml:"password"`
	PasswordEnv string `yaml:"password_env"`
	HardwareID  string `yaml:"hardware_id"`
	TLS         TLS    `yaml:"tls"`
}
type TLS struct {
	CAFile              string              `yaml:"ca_file"`
	ServerName          string              `yaml:"server_name"`
	InsecureSkipVerify  bool                `yaml:"insecure_skip_verify"`
	TrustedCertificates map[string][]string `yaml:"trusted_certificates"`
}

// SaveTrust updates only the certificate pins while preserving YAML comments.
// The temporary file lives alongside the destination so rename stays atomic.
func SaveTrust(path, origin, fingerprint string) error {
	origin, err := trust.CanonicalOrigin(origin)
	if err != nil {
		return fmt.Errorf("invalid certificate pin origin: %w", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(b) > 1<<20 {
		return errors.New("configuration exceeds 1 MiB")
	}
	var doc yaml.Node
	decoder := yaml.NewDecoder(bytes.NewReader(b))
	if err = decoder.Decode(&doc); err != nil {
		return errors.New("cannot update invalid YAML configuration")
	}
	var extra yaml.Node
	if err = decoder.Decode(&extra); err != io.EOF {
		return errors.New("configuration must contain exactly one YAML document")
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return errors.New("configuration must be a YAML mapping")
	}
	child := func(parent *yaml.Node, key string, kind yaml.Kind) *yaml.Node {
		for i := 0; i+1 < len(parent.Content); i += 2 {
			if parent.Content[i].Value == key {
				return parent.Content[i+1]
			}
		}
		value := &yaml.Node{Kind: kind}
		parent.Content = append(parent.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, value)
		return value
	}
	vpn := child(doc.Content[0], "vpn", yaml.MappingNode)
	if vpn.Kind != yaml.MappingNode {
		return errors.New("vpn must be a mapping")
	}
	tlsNode := child(vpn, "tls", yaml.MappingNode)
	if tlsNode.Kind != yaml.MappingNode {
		return errors.New("vpn.tls must be a mapping")
	}
	pins := child(tlsNode, "trusted_certificates", yaml.MappingNode)
	if pins.Kind != yaml.MappingNode {
		return errors.New("trusted_certificates must be a mapping")
	}
	// One active pin per origin; rotation requires a fresh explicit trust decision.
	// Update every equivalent origin key, including manually entered spellings
	// without the default port, so an alias cannot retain a superseded pin.
	updated := false
	for i := 0; i+1 < len(pins.Content); i += 2 {
		canonical, err := trust.CanonicalOrigin(pins.Content[i].Value)
		if err != nil || canonical != origin {
			continue
		}
		list := pins.Content[i+1]
		if list.Kind != yaml.SequenceNode {
			return errors.New("certificate pins must be a sequence")
		}
		list.Content = []*yaml.Node{{Kind: yaml.ScalarNode, Tag: "!!str", Value: fingerprint}}
		updated = true
	}
	if !updated {
		child(pins, origin, yaml.SequenceNode).Content = []*yaml.Node{{Kind: yaml.ScalarNode, Tag: "!!str", Value: fingerprint}}
	}
	out, err := yaml.Marshal(&doc)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".vpn-config-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(out)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

type SOCKS5 struct {
	Listen         string `yaml:"listen"`
	Username       string `yaml:"username"`
	Password       string `yaml:"password"`
	MaxConnections int    `yaml:"max_connections"`
}
type Timeouts struct {
	Connect   time.Duration `yaml:"connect"`
	Handshake time.Duration `yaml:"handshake"`
}

func Load(path string) (Config, error) {
	c := Config{SOCKS5: SOCKS5{Listen: "127.0.0.1:1080", MaxConnections: 128}, Timeouts: Timeouts{Connect: 20 * time.Second, Handshake: 30 * time.Second}}
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	contents, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return c, err
	}
	if len(contents) > 1<<20 {
		return c, errors.New("configuration exceeds 1 MiB")
	}
	d := yaml.NewDecoder(bytes.NewReader(contents))
	d.KnownFields(true)
	if err = d.Decode(&c); err != nil {
		return c, fmt.Errorf("parse YAML: %w", err)
	}
	var extra any
	if err = d.Decode(&extra); err != io.EOF {
		return c, errors.New("configuration must contain exactly one YAML document")
	}
	if c.VPN.PasswordEnv != "" {
		if c.VPN.Password != "" {
			return c, errors.New("set vpn.password or vpn.password_env, not both")
		}
		var ok bool
		c.VPN.Password, ok = os.LookupEnv(c.VPN.PasswordEnv)
		if !ok {
			return c, errors.New("vpn.password_env names an unset environment variable")
		}
	}
	if c.VPN.TLS.CAFile != "" && !filepath.IsAbs(c.VPN.TLS.CAFile) {
		c.VPN.TLS.CAFile = filepath.Join(filepath.Dir(path), c.VPN.TLS.CAFile)
	}
	return c, c.Validate()
}

func (c Config) Validate() error {
	if c.VPN.TLS.InsecureSkipVerify {
		return errors.New("vpn.tls.insecure_skip_verify is not supported; use a CA file or explicitly trust the certificate at startup")
	}
	u, err := url.Parse(c.VPN.Server)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("vpn.server must be an HTTPS origin, e.g. https://vpn.example.com:443")
	}
	if strings.ContainsAny(c.VPN.Server, "\r\n") {
		return errors.New("invalid vpn.server")
	}
	if u.Port() != "" {
		if port, err := strconv.ParseUint(u.Port(), 10, 16); err != nil || port == 0 {
			return errors.New("invalid VPN port")
		}
	}
	if c.VPN.Username == "" || c.VPN.Password == "" {
		return errors.New("vpn.username and password are required")
	}
	if c.VPN.Server == "https://vpn.example.com:443" || c.VPN.Username == "your-username" || c.VPN.Password == "your-password" {
		return errors.New("replace the example VPN connection values")
	}
	host, portText, err := net.SplitHostPort(c.SOCKS5.Listen)
	if err != nil {
		return errors.New("socks5.listen must be IP:port")
	}
	if port, err := strconv.ParseUint(portText, 10, 16); err != nil || port == 0 {
		return errors.New("socks5.listen port must be 1..65535")
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return errors.New("socks5.listen must use a literal IP address")
	}
	if (c.SOCKS5.Username == "") != (c.SOCKS5.Password == "") {
		return errors.New("set both SOCKS5 username and password")
	}
	if !ip.IsLoopback() && c.SOCKS5.Username == "" {
		return errors.New("SOCKS5 authentication is required for a non-loopback listener")
	}
	if len(c.SOCKS5.Username) > 255 || len(c.SOCKS5.Password) > 255 {
		return errors.New("SOCKS5 credentials exceed 255 bytes")
	}
	if c.SOCKS5.MaxConnections < 1 || c.SOCKS5.MaxConnections > 65536 {
		return errors.New("socks5.max_connections must be 1..65536")
	}
	if c.Timeouts.Connect <= 0 || c.Timeouts.Handshake <= 0 {
		return errors.New("timeouts must be positive durations")
	}
	return nil
}

func (c TLS) Build() (*tls.Config, error) {
	t := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: c.ServerName} // Self-signed trust is handled by the startup certificate verifier.
	if c.CAFile != "" {
		p, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read VPN CA: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(p) {
			return nil, errors.New("vpn.tls.ca_file contains no PEM certificates")
		}
		t.RootCAs = pool
	}
	return t, nil
}
