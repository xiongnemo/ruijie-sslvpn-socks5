package vpnauth

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type lockedLogBuffer struct {
	mu sync.Mutex
	bytes.Buffer
}

func (b *lockedLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.Write(p)
}

func (b *lockedLogBuffer) text() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.String()
}

// The gateway log contains a complete chunked/gzip fragment left on an idle
// HTTP connection. Reproduce both a no-body status with a forbidden body and
// a normal response followed by extra chunks. HTTP response parsing remains
// strict; isolated control connections keep surplus bytes out of the idle pool.
func TestLoginIsolatesSurplusHTTPResponseBytes(t *testing.T) {
	for _, status := range []int{http.StatusNoContent, http.StatusOK} {
		for _, reuseControl := range []bool{true, false} {
			name := fmt.Sprintf("status%d/default", status)
			if reuseControl {
				name = fmt.Sprintf("status%d/reuse-negative-control", status)
			}
			t.Run(name, func(t *testing.T) {
				var captured lockedLogBuffer
				originalWriter := log.Writer()
				log.SetOutput(&captured)
				defer log.SetOutput(originalWriter)
				gzipChunk := func(text string) []byte {
					var compressed bytes.Buffer
					writer := gzip.NewWriter(&compressed)
					if _, err := io.WriteString(writer, text); err != nil {
						t.Fatal(err)
					}
					if err := writer.Close(); err != nil {
						t.Fatal(err)
					}
					return append(append([]byte(fmt.Sprintf("%x\r\n", compressed.Len())), compressed.Bytes()...), []byte("\r\n0\r\n\r\n")...)
				}
				var response bytes.Buffer
				fmt.Fprintf(&response, "HTTP/1.1 %d %s\r\n", status, http.StatusText(status))
				io.WriteString(&response, "Set-Cookie: s_funcset1=1; Path=/; Secure\r\nSet-Cookie: rjsslvpnSID=synthetic-session; Path=/; Secure\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n")
				if status == http.StatusOK {
					response.Write(gzipChunk("landing page"))
				}
				response.Write(gzipChunk("synthetic surplus response data"))
				closed := make(chan struct{})
				params := []byte{1, 2, 3, 4}
				srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/" {
						conn, buffered, err := w.(http.Hijacker).Hijack()
						if err != nil {
							t.Error(err)
							close(closed)
							return
						}
						defer close(closed)
						defer conn.Close()
						_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
						if _, err := buffered.Write(response.Bytes()); err != nil {
							t.Error(err)
							return
						}
						if err := buffered.Flush(); err != nil {
							t.Error(err)
							return
						}
						// Either the compatibility policy or Go's rejected idle
						// bytes must close this connection before the next request.
						if _, err := buffered.ReadByte(); err != io.EOF {
							t.Errorf("expected isolated control connection to close: %v", err)
						}
						return
					}
					if r.URL.Path != "/sslvpn/action/loginv2" {
						http.NotFound(w, r)
						return
					}
					cookie, err := r.Cookie("rjsslvpnSID")
					if err != nil || cookie.Value != "synthetic-session" {
						t.Error("session cookies were not preserved across control connections")
					}
					fmt.Fprintf(w, `{"code":"0","data":{"iptunParam":%q}}`, base64.StdEncoding.EncodeToString(params))
				}))
				defer srv.Close()
				c := newTestClient(t, srv)
				if reuseControl {
					c.http.Transport.(*http.Transport).DisableKeepAlives = false
				}
				session, err := c.Login(context.Background())
				if err != nil || session == nil || !bytes.Equal(session.TunnelParameters, params) {
					t.Fatalf("login with surplus response bytes failed: %v", err)
				}
				select {
				case <-closed:
				case <-time.After(3 * time.Second):
					t.Fatal("malformed control connection stayed open")
				}
				c.Close()
				warning := strings.Contains(captured.text(), "Unsolicited response received on idle HTTP channel")
				if warning != reuseControl {
					t.Fatalf("idle response warning = %t; negative control = %t", warning, reuseControl)
				}
			})
		}
	}
}
