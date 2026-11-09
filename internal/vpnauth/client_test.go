package vpnauth

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func decryptForServer(t *testing.T, encoded string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) < 32 || len(b)%16 != 0 {
		t.Fatalf("invalid credential envelope length %d", len(b))
	}
	cipherBlock, err := aes.NewCipher(b[:16])
	if err != nil {
		t.Fatal(err)
	}
	iv := append([]byte("sslvpnauthr5"), make([]byte, 5)...)
	iv = iv[:16]
	out := make([]byte, len(b)-16)
	cipher.NewCBCDecrypter(cipherBlock, iv).CryptBlocks(out, b[16:])
	n := int(out[len(out)-1])
	if n < 1 || n > 16 || n > len(out) {
		t.Fatal("invalid credential padding")
	}
	if !bytes.Equal(out[len(out)-n:], bytes.Repeat([]byte{byte(n)}, n)) {
		t.Fatal("invalid credential padding bytes")
	}
	return out[:len(out)-n]
}

func newTestClient(t *testing.T, s *httptest.Server) *Client {
	t.Helper()
	c, err := New(Options{Server: s.URL, Username: "test+name", Password: "test&password+", HardwareID: "test-device", TLSConfig: s.Client().Transport.(*http.Transport).TLSClientConfig, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func TestLoginV2NegotiatesAndEncryptsCredentials(t *testing.T) {
	params := []byte{3, 0, 4, 10, 1, 2, 3}
	var postCount atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			if c, err := r.Cookie("c_funcset1"); err != nil || c.Value != "127" {
				t.Error("missing native client capabilities")
			}
			http.SetCookie(w, &http.Cookie{Name: "s_funcset1", Value: "9", Path: "/", Secure: true})
			http.SetCookie(w, &http.Cookie{Name: "rjsslvpnSID", Value: "test-session", Path: "/", Secure: true, HttpOnly: true})
			_, _ = io.WriteString(w, "landing page")
		case "/sslvpn/action/loginv2":
			postCount.Add(1)
			if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
				t.Error("wrong JSON login request")
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
				http.Error(w, "bad json", 400)
				return
			}
			if body["uname"] != "test+name" || body["hid"] != "test-device" || body["terminal"] != "win" || body["verifycode"] != "6" || body["realm"] != "user" || body["updateSession"] != true {
				t.Error("native login parameters differ")
			}
			if plain := decryptForServer(t, body["pwd"].(string)); string(plain) != "test&password+" {
				t.Error("password envelope mismatch")
			}
			var credential map[string]string
			if err := json.Unmarshal(decryptForServer(t, body["passwd2"].(string)), &credential); err != nil {
				t.Error(err)
			}
			if credential["uname"] != "test+name" || credential["passwd"] != "test&password+" || credential["sid"] != "test-session" {
				t.Error("bound session credential mismatch")
			}
			http.SetCookie(w, &http.Cookie{Name: "rjsslvpnSID", Value: "authenticated-session", Path: "/", Secure: true, HttpOnly: true})
			fmt.Fprintf(w, `{"code":"0","data":{"iptunParam":%q}}`, base64.StdEncoding.EncodeToString(params))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := newTestClient(t, srv)
	session, err := c.Login(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(session.TunnelParameters, params) {
		t.Fatal("tunnel document was not decoded")
	}
	if !strings.Contains(session.Cookie, "rjsslvpnSID=authenticated-session") || strings.Contains(session.Cookie, "c_") {
		t.Fatal("wrong tunnel cookie selection")
	}
	if strings.Contains(fmt.Sprint(session), "authenticated-session") {
		t.Fatal("formatting leaked cookie")
	}
	if postCount.Load() != 1 {
		t.Fatal("login sent more than once")
	}
	if !session.ExtendedHeartbeat {
		t.Fatal("server's extended heartbeat capability was not retained")
	}
}

func TestLegacyLoginSecAndTunnelParameters(t *testing.T) {
	var logout atomic.Bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			http.SetCookie(w, &http.Cookie{Name: "s_funcset1", Value: "16", Path: "/", Secure: true})
			http.SetCookie(w, &http.Cookie{Name: "rjsslvpnSID", Value: "legacy-session", Path: "/", Secure: true})
		case "/sslvpn/action/loginSec":
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			if r.Form.Get("username") != "test+name" || r.Form.Get("realm") != "user" {
				t.Error("form was not escaped correctly")
			}
			if plain := decryptForServer(t, r.Form.Get("password")); string(plain) != "test&password+" {
				t.Error("legacy encryption differs")
			}
			_, _ = io.WriteString(w, `<script>window.location="login_ok.html"</script>`)
		case "/sslvpn/action/getIPAccessParam":
			if len(r.URL.Query().Get("arg")) != 7 {
				t.Error("missing cache buster")
			}
			_, _ = io.WriteString(w, "AQIDBA==")
		case "/sslvpn/action/logout":
			if r.Method != http.MethodGet || len(r.URL.Query().Get("arg")) != 7 {
				t.Error("logout omitted the native seven-digit cache buster")
			}
			logout.Store(true)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := newTestClient(t, srv)
	session, err := c.Login(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(session.TunnelParameters, []byte{1, 2, 3, 4}) {
		t.Fatal("legacy tunnel parameters mismatch")
	}
	if session.ExtendedHeartbeat {
		t.Fatal("enabled extended heartbeat without server capability bit 0x08")
	}
	if err := c.Logout(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !logout.Load() {
		t.Fatal("logout not requested")
	}
}

func TestAuthenticationFailureNeverDowngradesOrRetries(t *testing.T) {
	var posts atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.SetCookie(w, &http.Cookie{Name: "s_funcset1", Value: "1", Path: "/", Secure: true})
			http.SetCookie(w, &http.Cookie{Name: "rjsslvpnSID", Value: "negotiated-session", Path: "/", Secure: true})
			return
		}
		posts.Add(1)
		_, _ = io.WriteString(w, `{"code":"7","data":{"extMsg":"do not echo server content"}}`)
	}))
	defer srv.Close()
	c := newTestClient(t, srv)
	_, err := c.Login(context.Background())
	var authErr *AuthError
	if !errors.As(err, &authErr) || authErr.Code != 7 {
		t.Fatalf("expected code7 authentication error; got %v", err)
	}
	if posts.Load() != 1 {
		t.Fatal("failed login was retried")
	}
	if strings.Contains(err.Error(), "echo server") {
		t.Fatal("error disclosed raw server response")
	}
}

func TestTLSVerificationCallbackPreserved(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer srv.Close()
	var called atomic.Bool
	tc := srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	sentinel := errors.New("certificate explicitly rejected")
	tc.VerifyConnection = func(tls.ConnectionState) error { called.Store(true); return sentinel }
	c, err := New(Options{Server: srv.URL, Username: "u", Password: "p", TLSConfig: tc})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, err = c.Login(context.Background())
	if !called.Load() || !errors.Is(err, sentinel) {
		t.Fatalf("certificate trust callback was bypassed: %v", err)
	}
}

func TestMalformedLoginResponses(t *testing.T) {
	for _, body := range []string{`{}`, `{"data":{}}`, `{"code":"bad"}`, `{"code":"0","data":{}}`, `{"code":"0","data":{"iptunParam":123}}`, `{"code":"0","data":{"iptunParam":"a"}}junk`} {
		if _, err := parseLoginJSON([]byte(body)); err == nil {
			t.Errorf("accepted malformed login response %q", body)
		}
	}
}

func TestPasswordEnvelopeOpenSSLVector(t *testing.T) {
	// Independently generated with OpenSSL enc -aes-128-cbc, PKCS#7 enabled,
	// key 000102030405060708090a0b0c0d0e0f and IV 73736c76706e61757468723500000000.
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}
	const want = "AAECAwQFBgcICQoLDA0ODwidWFQjRua6nVbDcUASKsg="
	if got := encryptWithKey([]byte("correct horse"), key); got != want {
		t.Fatalf("password envelope differs from OpenSSL vector: %s", got)
	}
}
