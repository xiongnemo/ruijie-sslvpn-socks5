// Package vpnauth implements the password login flows observed in RG-SSLVPN 2.5.0.
// Protocol sources are the static Ghidra exports listed in analysis/PROTOCOL.md.
package vpnauth

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const maxResponseBytes = 2 << 20

type Options struct {
	Server, Username, Password, HardwareID string
	TLSConfig                              *tls.Config
	Timeout                                time.Duration
}

type Client struct {
	options Options
	origin  *url.URL
	http    *http.Client
}

type Session struct {
	// TunnelParameters is the decoded iptunParam TLV document, not JSON.
	TunnelParameters        []byte
	EncodedTunnelParameters string
	Cookie                  string
	// ExtendedHeartbeat is the native bUseDtlsV2 capability, negotiated by
	// s_funcset1 bit 0x08. It controls application heartbeats, not DTLS version.
	ExtendedHeartbeat bool
}

// String prevents accidental credential logging when a session is formatted.
func (s Session) String() string { return "VPN session (credentials redacted)" }

type AuthError struct{ Code int }

func (e *AuthError) Error() string {
	switch {
	case e.Code == 7 || e.Code == 27:
		return fmt.Sprintf("VPN authentication rejected (code %d): check username and password", e.Code)
	case e.Code >= 96 && e.Code <= 110 || e.Code >= 128 && e.Code <= 143 || e.Code >= 20000:
		return fmt.Sprintf("VPN authentication requires an additional verification step (code %d)", e.Code)
	default:
		return fmt.Sprintf("VPN authentication rejected (code %d)", e.Code)
	}
}

func New(o Options) (*Client, error) {
	u, err := url.Parse(o.Server)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("VPN server must be an HTTPS origin")
	}
	if o.Username == "" || o.Password == "" {
		return nil, errors.New("VPN username and password are required")
	}
	if o.Timeout <= 0 {
		o.Timeout = 20 * time.Second
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if o.TLSConfig != nil {
		tc = o.TLSConfig.Clone()
	}
	jar, _ := cookiejar.New(nil)
	jar.SetCookies(u, []*http.Cookie{
		{Name: "c_funcset1", Value: "127", Path: "/", Secure: true},
		{Name: "c_version", Value: "2.5.0", Path: "/", Secure: true},
		{Name: "c_osinfo", Value: "Windows", Path: "/", Secure: true},
	})
	tr := &http.Transport{TLSClientConfig: tc, Proxy: nil, ForceAttemptHTTP2: false,
		// Some gateways send surplus chunked/gzip bytes after a complete
		// response. Keep the few authentication/control requests on separate
		// connections so those bytes cannot enter an idle HTTP connection.
		// Cookies and mandatory TLS verification still apply to every request.
		DisableKeepAlives:   true,
		DialContext:         (&net.Dialer{Timeout: o.Timeout}).DialContext,
		TLSHandshakeTimeout: o.Timeout, ResponseHeaderTimeout: o.Timeout}
	c := &Client{options: o, origin: u}
	c.http = &http.Client{Transport: tr, Jar: jar, Timeout: o.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("too many VPN redirects")
			}
			if req.URL.Scheme != u.Scheme || !strings.EqualFold(req.URL.Host, u.Host) {
				return errors.New("VPN redirected outside the configured origin")
			}
			return nil
		}}
	return c, nil
}

func (c *Client) Close() { c.http.CloseIdleConnections() }

// Login negotiates the server-advertised password flow. Failed authentication is
// returned immediately; it is never retried using a weaker login endpoint.
func (c *Client) Login(ctx context.Context) (*Session, error) {
	if _, _, err := c.request(ctx, http.MethodGet, "/", "", nil); err != nil {
		return nil, fmt.Errorf("VPN negotiation: %w", err)
	}
	features, err := c.features()
	if err != nil {
		return nil, err
	}
	var path, contentType string
	var payload []byte
	if features&1 != 0 {
		path = "/sslvpn/action/loginv2"
		contentType = "application/json"
		sid := c.cookie("rjsslvpnSID")
		if sid == "" {
			return nil, errors.New("VPN loginv2 negotiation omitted its session cookie")
		}
		pwd, err := encryptPassword([]byte(c.options.Password))
		if err != nil {
			return nil, err
		}
		credentialJSON, err := json.Marshal(map[string]string{"uname": c.options.Username, "passwd": c.options.Password, "sid": sid})
		if err != nil {
			return nil, err
		}
		passwd2, err := encryptPassword(credentialJSON)
		if err != nil {
			return nil, err
		}
		payload, err = json.Marshal(map[string]any{"uname": c.options.Username, "pwd": pwd, "passwd2": passwd2, "terminal": "win", "realm": "user", "hidDesc": "", "verifycode": "6", "updateSession": true, "hid": c.options.HardwareID})
		if err != nil {
			return nil, err
		}
	} else {
		path = "/sslvpn/action/login"
		contentType = "application/x-www-form-urlencoded"
		password := c.options.Password
		if features&16 != 0 {
			path = "/sslvpn/action/loginSec"
			password, err = encryptPassword([]byte(password))
			if err != nil {
				return nil, err
			}
		}
		payload = []byte(url.Values{"realm": {"user"}, "username": {c.options.Username}, "password": {password}, "verifycode": {"6"}, "terminal": {"win"}}.Encode())
	}
	body, finalURL, err := c.request(ctx, http.MethodPost, path, contentType, payload)
	if err != nil {
		return nil, fmt.Errorf("VPN login: %w", err)
	}
	var encoded string
	if features&1 != 0 {
		encoded, err = parseLoginJSON(body)
		if err != nil {
			return nil, err
		}
	} else if bytes.Contains(body, []byte("login_ok.html")) || bytes.Contains(body, []byte("note.html")) || strings.HasSuffix(finalURL.Path, "/login_ok.html") || strings.HasSuffix(finalURL.Path, "/note.html") {
		nonce, err := rand.Int(rand.Reader, big.NewInt(9000000))
		if err != nil {
			return nil, err
		}
		paramBody, _, err := c.request(ctx, http.MethodGet, "/sslvpn/action/getIPAccessParam?arg="+strconv.FormatInt(nonce.Int64()+1000000, 10), "", nil)
		if err != nil {
			return nil, fmt.Errorf("VPN tunnel parameters: %w", err)
		}
		encoded = strings.TrimSpace(string(paramBody))
	} else {
		// Some gateways return the JSON response with the legacy endpoint too.
		if len(bytes.TrimSpace(body)) > 0 && bytes.TrimSpace(body)[0] == '{' {
			encoded, err = parseLoginJSON(body)
			if err != nil {
				return nil, err
			}
		} else {
			if m := legacyCode.FindSubmatch(body); m != nil {
				code, _ := strconv.Atoi(string(m[1]))
				return nil, &AuthError{Code: code}
			}
			if code, err := strconv.Atoi(finalURL.Query().Get("code")); err == nil {
				return nil, &AuthError{Code: code}
			}
			return nil, errors.New("VPN returned an unrecognized login response")
		}
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(decoded) == 0 {
		return nil, errors.New("VPN returned invalid base64 tunnel parameters")
	}
	// The native TLS tunnel sends the rjsslvpn session cookie, not client metadata.
	var cookies []string
	for _, cookie := range c.http.Jar.Cookies(c.cookieURL()) {
		if !strings.HasPrefix(cookie.Name, "c_") {
			cookies = append(cookies, cookie.Name+"="+cookie.Value)
		}
	}
	if len(cookies) == 0 {
		return nil, errors.New("VPN authentication returned no session cookies")
	}
	return &Session{TunnelParameters: decoded, EncodedTunnelParameters: encoded, Cookie: strings.Join(cookies, "; "), ExtendedHeartbeat: features&8 != 0}, nil
}

var legacyCode = regexp.MustCompile(`(?:[?&]|&amp;)code=([0-9]+)`)

func (c *Client) cookieURL() *url.URL { u := *c.origin; u.Path = "/sslvpn/action/loginv2"; return &u }
func (c *Client) cookie(name string) string {
	for _, cookie := range c.http.Jar.Cookies(c.cookieURL()) {
		if cookie.Name == name {
			return cookie.Value
		}
	}
	return ""
}
func (c *Client) features() (uint64, error) {
	s := c.cookie("s_funcset1")
	if s == "" {
		return 0, nil
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, errors.New("VPN returned invalid capability flags")
	}
	return n, nil
}

func (c *Client) Logout(ctx context.Context) error {
	// Native FUN_18008e4b0 appends a seven-digit arg to the logout URL too.
	// Some gateways return HTTP 400 when this query parameter is missing.
	nonce, err := rand.Int(rand.Reader, big.NewInt(9000000))
	if err != nil {
		return err
	}
	_, _, err = c.request(ctx, http.MethodGet, "/sslvpn/action/logout?arg="+strconv.FormatInt(nonce.Int64()+1000000, 10), "", nil)
	return err
}

func (c *Client) request(ctx context.Context, method, path, contentType string, body []byte) ([]byte, *url.URL, error) {
	ref, err := url.Parse(path)
	if err != nil {
		return nil, nil, err
	}
	target := c.origin.ResolveReference(ref)
	req, err := http.NewRequestWithContext(ctx, method, target.String(), bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Accept", "*/*")
	req.Header.Set("User-Agent", "RG-SSLVPN/2.5.0")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes+1))
	if err != nil {
		return nil, nil, err
	}
	if len(data) > maxResponseBytes {
		return nil, nil, errors.New("VPN response exceeds 2 MiB")
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, nil, fmt.Errorf("VPN HTTP status %d", res.StatusCode)
	}
	return data, res.Request.URL, nil
}

func parseLoginJSON(body []byte) (string, error) {
	var response struct {
		Code json.RawMessage `json:"code"`
		Data struct {
			Parameters string `json:"iptunParam"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return "", errors.New("VPN returned malformed login JSON")
	}
	var codeText string
	if len(response.Code) == 0 {
		return "", errors.New("VPN login response omitted its result code")
	}
	if response.Code[0] == '"' {
		if err := json.Unmarshal(response.Code, &codeText); err != nil {
			return "", errors.New("VPN returned an invalid result code")
		}
	} else {
		codeText = string(response.Code)
	}
	code, err := strconv.Atoi(codeText)
	if err != nil {
		return "", errors.New("VPN returned an invalid result code")
	}
	if code != 0 {
		return "", &AuthError{Code: code}
	}
	if response.Data.Parameters == "" {
		return "", errors.New("VPN login response omitted tunnel parameters")
	}
	return response.Data.Parameters, nil
}

// Native FUN_180082cd0: AES-128-CBC, PKCS#7, random key || ciphertext,
// standard base64. The key is carried by the application protocol; transport
// confidentiality relies on the authenticated HTTPS connection.
func encryptPassword(plain []byte) (string, error) {
	key := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", err
	}
	return encryptWithKey(plain, key), nil
}
func encryptWithKey(plain, key []byte) string {
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	padded := make([]byte, len(plain)+pad)
	copy(padded, plain)
	for i := len(plain); i < len(padded); i++ {
		padded[i] = byte(pad)
	}
	block, _ := aes.NewCipher(key)
	iv := make([]byte, aes.BlockSize)
	copy(iv, "sslvpnauthr5")
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(padded, padded)
	output := append(append(make([]byte, 0, len(key)+len(padded)), key...), padded...)
	return base64.StdEncoding.EncodeToString(output)
}
