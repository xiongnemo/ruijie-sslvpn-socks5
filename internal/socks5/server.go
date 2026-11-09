// Package socks5 implements a SOCKS5 TCP CONNECT listener whose outbound
// connections are supplied by the caller. It never falls back to the host's
// network dialer.
package socks5

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// DialContextFunc must connect through the intended VPN transport. The server
// supplies network "tcp" and an IP or domain with its port, and cancels the
// context when the server stops or the connect timeout expires.
type DialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

// Config controls the SOCKS listener. A username and password enable RFC 1929
// authentication; both must be set together. Zero limits select the defaults.
type Config struct {
	DialContext      DialContextFunc
	Username         string
	Password         string
	HandshakeTimeout time.Duration
	ConnectTimeout   time.Duration
	MaxConnections   int
}

// Server serves SOCKS5 CONNECT requests. A Server supports one Serve call at a
// time. Create the listener separately to choose its bind address; normally use
// a loopback address, such as 127.0.0.1:1080.
type Server struct {
	config Config
	mu     sync.Mutex
	active bool
}

// New validates configuration. In particular, an explicit outbound dialer is
// mandatory, so a missing VPN can never silently create a direct proxy.
func New(config Config) (*Server, error) {
	if config.DialContext == nil {
		return nil, errors.New("socks5: an outbound DialContext is required")
	}
	if (config.Username == "") != (config.Password == "") {
		return nil, errors.New("socks5: username and password must be set together")
	}
	if len(config.Username) > 255 || len(config.Password) > 255 {
		return nil, errors.New("socks5: credentials must be at most 255 bytes each")
	}
	if config.HandshakeTimeout < 0 || config.ConnectTimeout < 0 || config.MaxConnections < 0 {
		return nil, errors.New("socks5: timeouts and connection limit must not be negative")
	}
	if config.HandshakeTimeout == 0 {
		config.HandshakeTimeout = 10 * time.Second
	}
	if config.ConnectTimeout == 0 {
		config.ConnectTimeout = 30 * time.Second
	}
	if config.MaxConnections == 0 {
		config.MaxConnections = 256
	}
	return &Server{config: config}, nil
}

// Serve takes ownership of listener and serves until ctx is canceled or Accept
// fails. On return the listener, all inbound connections and all successfully
// dialed outbound connections are closed, and handlers have exited. Cancellation
// returns ctx.Err(). A dialer must honor its context to permit prompt shutdown.
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	if listener == nil {
		return errors.New("socks5: listener is required")
	}
	s.mu.Lock()
	if s.active {
		s.mu.Unlock()
		return errors.New("socks5: server is already serving")
	}
	s.active = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.active = false
		s.mu.Unlock()
	}()

	serveCtx, cancel := context.WithCancel(ctx)
	var clientsMu sync.Mutex
	clients := make(map[net.Conn]struct{})
	var handlers sync.WaitGroup
	slots := make(chan struct{}, s.config.MaxConnections)
	stop := context.AfterFunc(serveCtx, func() {
		listener.Close()
		clientsMu.Lock()
		for conn := range clients {
			conn.Close()
		}
		clientsMu.Unlock()
	})
	defer func() {
		cancel()
		listener.Close()
		clientsMu.Lock()
		for conn := range clients {
			conn.Close()
		}
		clientsMu.Unlock()
		handlers.Wait()
		stop()
	}()

	var retryDelay time.Duration
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if transient, ok := err.(net.Error); ok && transient.Temporary() {
				if retryDelay == 0 {
					retryDelay = 5 * time.Millisecond
				} else {
					retryDelay *= 2
				}
				if retryDelay > time.Second {
					retryDelay = time.Second
				}
				timer := time.NewTimer(retryDelay)
				select {
				case <-timer.C:
				case <-ctx.Done():
					timer.Stop()
					return ctx.Err()
				}
				continue
			}
			return fmt.Errorf("socks5: accept: %w", err)
		}
		retryDelay = 0
		select {
		case slots <- struct{}{}:
		default:
			conn.Close()
			continue
		}
		clientsMu.Lock()
		if serveCtx.Err() != nil {
			clientsMu.Unlock()
			conn.Close()
			<-slots
			return ctx.Err()
		}
		clients[conn] = struct{}{}
		clientsMu.Unlock()
		handlers.Add(1)
		go func() {
			defer handlers.Done()
			defer func() { <-slots }()
			defer func() {
				conn.Close()
				clientsMu.Lock()
				delete(clients, conn)
				clientsMu.Unlock()
			}()
			s.handle(serveCtx, conn)
		}()
	}
}

func (s *Server) handle(ctx context.Context, client net.Conn) {
	if err := client.SetDeadline(time.Now().Add(s.config.HandshakeTimeout)); err != nil {
		return
	}
	if err := s.authenticate(client); err != nil {
		return
	}
	address, code, err := readRequest(client)
	if err != nil {
		if code != 0 {
			writeReply(client, code, nil)
		}
		return
	}
	connectCtx, cancel := context.WithTimeout(ctx, s.config.ConnectTimeout)
	remote, err := s.config.DialContext(connectCtx, "tcp", address)
	cancel()
	if err != nil || remote == nil {
		if remote != nil {
			remote.Close()
		}
		client.SetWriteDeadline(time.Now().Add(s.config.HandshakeTimeout))
		writeReply(client, dialErrorCode(err), nil)
		return
	}
	defer remote.Close()
	stop := context.AfterFunc(ctx, func() { remote.Close() })
	defer stop()
	if ctx.Err() != nil {
		return
	}
	if err := client.SetWriteDeadline(time.Now().Add(s.config.HandshakeTimeout)); err != nil {
		return
	}
	if err := writeReply(client, 0, remote.LocalAddr()); err != nil {
		return
	}
	if err := client.SetDeadline(time.Time{}); err != nil {
		return
	}
	relay(client, remote)
}

func (s *Server) authenticate(conn net.Conn) error {
	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return err
	}
	if header[0] != 5 {
		return errors.New("unsupported SOCKS version")
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	method := byte(0)
	if s.config.Username != "" {
		method = 2
	}
	accepted := false
	for _, offered := range methods {
		if method == offered {
			accepted = true
		}
	}
	if !accepted {
		writeAll(conn, []byte{5, 255})
		return errors.New("no acceptable authentication method")
	}
	if err := writeAll(conn, []byte{5, method}); err != nil {
		return err
	}
	if method == 0 {
		return nil
	}
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return err
	}
	if header[0] != 1 || header[1] == 0 {
		writeAll(conn, []byte{1, 1})
		return errors.New("invalid authentication request")
	}
	username := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, username); err != nil {
		return err
	}
	var length [1]byte
	if _, err := io.ReadFull(conn, length[:]); err != nil {
		return err
	}
	if length[0] == 0 {
		writeAll(conn, []byte{1, 1})
		return errors.New("invalid authentication request")
	}
	password := make([]byte, int(length[0]))
	if _, err := io.ReadFull(conn, password); err != nil {
		return err
	}
	actualUser, expectedUser := sha256.Sum256(username), sha256.Sum256([]byte(s.config.Username))
	actualPass, expectedPass := sha256.Sum256(password), sha256.Sum256([]byte(s.config.Password))
	valid := subtle.ConstantTimeCompare(actualUser[:], expectedUser[:]) & subtle.ConstantTimeCompare(actualPass[:], expectedPass[:])
	if valid != 1 {
		writeAll(conn, []byte{1, 1})
		return errors.New("authentication failed")
	}
	return writeAll(conn, []byte{1, 0})
}

func readRequest(conn io.Reader) (address string, replyCode byte, err error) {
	var header [4]byte
	if _, err = io.ReadFull(conn, header[:]); err != nil {
		return "", 0, err
	}
	if header[0] != 5 || header[2] != 0 {
		return "", 1, errors.New("invalid request header")
	}
	var host string
	switch header[3] {
	case 1:
		var raw [4]byte
		if _, err = io.ReadFull(conn, raw[:]); err != nil {
			return "", 0, err
		}
		host = net.IP(raw[:]).String()
	case 3:
		var length [1]byte
		if _, err = io.ReadFull(conn, length[:]); err != nil {
			return "", 0, err
		}
		if length[0] == 0 {
			return "", 8, errors.New("empty destination host")
		}
		raw := make([]byte, int(length[0]))
		if _, err = io.ReadFull(conn, raw); err != nil {
			return "", 0, err
		}
		host = string(raw)
	case 4:
		var raw [16]byte
		if _, err = io.ReadFull(conn, raw[:]); err != nil {
			return "", 0, err
		}
		host = net.IP(raw[:]).String()
	default:
		return "", 8, errors.New("unsupported address type")
	}
	var portBytes [2]byte
	if _, err = io.ReadFull(conn, portBytes[:]); err != nil {
		return "", 0, err
	}
	// Consume the complete request before rejecting a command. Closing a TCP
	// socket with unread request bytes may reset it and discard the reply.
	if header[1] != 1 {
		return "", 7, errors.New("only TCP CONNECT is supported")
	}
	if strings.IndexByte(host, 0) >= 0 {
		return "", 8, errors.New("invalid destination host")
	}
	port := binary.BigEndian.Uint16(portBytes[:])
	if port == 0 {
		return "", 1, errors.New("destination port must not be zero")
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port))), 0, nil
}

func writeReply(conn io.Writer, code byte, bound net.Addr) error {
	ip := net.IPv4zero
	port := 0
	if bound != nil {
		if host, portText, err := net.SplitHostPort(bound.String()); err == nil {
			if parsed := net.ParseIP(host); parsed != nil {
				if parsedPort, err := strconv.Atoi(portText); err == nil && parsedPort >= 0 && parsedPort <= 65535 {
					ip, port = parsed, parsedPort
				}
			}
		}
	}
	reply := []byte{5, code, 0, 1}
	if v4 := ip.To4(); v4 != nil {
		reply = append(reply, v4...)
	} else {
		reply[3] = 4
		reply = append(reply, ip.To16()...)
	}
	reply = append(reply, byte(port>>8), byte(port))
	return writeAll(conn, reply)
}

func dialErrorCode(err error) byte {
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return 5
	case errors.Is(err, syscall.ENETUNREACH):
		return 3
	case errors.Is(err, syscall.EHOSTUNREACH):
		return 4
	default:
		var dnsErr *net.DNSError
		var netErr net.Error
		if errors.As(err, &dnsErr) || (errors.As(err, &netErr) && netErr.Timeout()) {
			return 4
		}
		return 1
	}
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) != 0 {
		n, err := writer.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func relay(client, remote net.Conn) {
	var done sync.WaitGroup
	done.Add(2)
	copyStream := func(dst, src net.Conn) {
		defer done.Done()
		_, err := io.Copy(dst, src)
		if half, ok := dst.(interface{ CloseWrite() error }); ok && err == nil {
			if half.CloseWrite() == nil {
				return
			}
		}
		// A transport without half-close cannot signal EOF independently of
		// its read side. Close both ends rather than retain an idle connection.
		client.Close()
		remote.Close()
	}
	go copyStream(remote, client)
	go copyStream(client, remote)
	done.Wait()
}
