package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

type Configuration struct {
	Address netip.Addr
	Netmask netip.Addr
	DNS     []netip.Addr
	MTU     uint32
}
type Options struct {
	Compression       bool
	ExtendedHeartbeat bool
	Timeout           time.Duration
}
type pending struct {
	data    []byte
	sent    time.Time
	retries int
}
type Link struct {
	conn              net.Conn
	ctx               context.Context
	cancel            context.CancelFunc
	compression       bool
	writeMu           sync.Mutex
	mu                sync.Mutex
	cfg               Configuration
	cfgDone           bool
	sendSeq, recvSeq  uint16
	pending           map[uint16]*pending
	lastRecv          time.Time
	heartbeatHold     time.Duration
	heartbeatInterval time.Duration
	pingExtended      bool
	pingSeq           uint16
	sentFrames        uint64
	receivedFrames    uint64
	receivedAtPing    uint64
	peerReceived      uint64
	receiveLoss       uint64
	packets           chan []byte
	ready             chan struct{}
	changed           chan struct{}
	done              chan struct{}
	err               error
	closeOnce         sync.Once
}

// Connect negotiates the session ID and configuration over an authenticated
// DTLS datagram connection. It returns only after the server finishes config.
func Connect(ctx context.Context, conn net.Conn, sessionID []byte, options Options) (*Link, Configuration, error) {
	var zero Configuration
	if conn == nil || len(sessionID) != 32 {
		return nil, zero, errors.New("invalid tunnel connection or session ID")
	}
	if options.Timeout <= 0 {
		options.Timeout = 30 * time.Second
	}
	lc, cancel := context.WithCancel(ctx)
	l := &Link{conn: conn, ctx: lc, cancel: cancel, compression: options.Compression, pingExtended: options.ExtendedHeartbeat, cfg: Configuration{MTU: 1400}, recvSeq: 1, pending: make(map[uint16]*pending), lastRecv: time.Now(), heartbeatHold: 180 * time.Second, heartbeatInterval: 30 * time.Second, packets: make(chan []byte, 256), ready: make(chan struct{}), changed: make(chan struct{}, 1), done: make(chan struct{})}
	go l.readLoop()
	go l.maintain()
	initCtx, initCancel := context.WithTimeout(ctx, options.Timeout)
	defer initCancel()
	seq, err := l.control(append([]byte{1, 32}, sessionID...))
	if err == nil {
		err = l.waitACK(initCtx, seq)
	}
	if err == nil {
		_, err = l.control([]byte{2, 0})
	}
	if err == nil {
		select {
		case <-l.ready:
		case <-initCtx.Done():
			err = initCtx.Err()
		case <-l.done:
			err = l.Err()
		}
	}
	if err != nil {
		l.fail(err)
		return nil, zero, fmt.Errorf("negotiate VPN tunnel: %w", err)
	}
	l.mu.Lock()
	cfg := l.cfg
	currentErr := l.err
	cfg.DNS = append([]netip.Addr(nil), cfg.DNS...)
	l.mu.Unlock()
	if currentErr != nil {
		return nil, zero, currentErr
	}
	if !cfg.Address.IsValid() {
		l.fail(errors.New("gateway completed configuration without a virtual IP"))
		return nil, zero, l.Err()
	}
	return l, cfg, nil
}
func (l *Link) Done() <-chan struct{} { return l.done }
func (l *Link) Err() error            { l.mu.Lock(); defer l.mu.Unlock(); return l.err }
func (l *Link) fail(err error) {
	l.closeOnce.Do(func() {
		l.mu.Lock()
		l.err = err
		l.mu.Unlock()
		l.cancel()
		_ = l.conn.Close()
		close(l.done)
	})
}
func (l *Link) Close() error { l.fail(net.ErrClosed); return nil }

func (l *Link) send(data []byte) error {
	if len(data) > 65535 {
		return errors.New("tunnel datagram too large")
	}
	select {
	case <-l.done:
		return l.Err()
	default:
	}
	l.writeMu.Lock()
	defer l.writeMu.Unlock()
	extendedPing := len(data) == 39 && data[0] == 20
	if extendedPing {
		// Take the counters in send order, including this heartbeat. Native
		// counters cover all application frames, including control retries.
		l.mu.Lock()
		binary.BigEndian.PutUint16(data[5:7], l.pingSeq)
		binary.BigEndian.PutUint64(data[7:15], l.sentFrames+1)
		binary.BigEndian.PutUint64(data[15:23], l.receivedFrames)
		binary.BigEndian.PutUint64(data[23:31], l.peerReceived)
		binary.BigEndian.PutUint64(data[31:39], l.receiveLoss)
		l.mu.Unlock()
	}
	if l.compression {
		var err error
		data, err = compressPacket(data)
		if err != nil {
			return err
		}
	}
	if err := l.conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	n, err := l.conn.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err == nil {
		l.mu.Lock()
		l.sentFrames++
		if extendedPing {
			l.pingSeq++
		}
		l.mu.Unlock()
	}
	return err
}
func (l *Link) WritePacket(packet []byte) error {
	if len(packet) < 20 || packet[0]>>4 != 4 || int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) {
		return errors.New("invalid outgoing IPv4 packet")
	}
	return l.send(append([]byte{1}, packet...))
}
func (l *Link) ReadPacket(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-l.done:
		return nil, l.Err()
	case p := <-l.packets:
		return p, nil
	}
}
func (l *Link) control(tlv []byte) (uint16, error) {
	l.mu.Lock()
	l.sendSeq++
	seq := l.sendSeq
	b := make([]byte, 9+len(tlv))
	b[0] = 2
	b[1] = 1
	binary.BigEndian.PutUint16(b[3:5], uint16(len(tlv)))
	binary.BigEndian.PutUint16(b[5:7], seq)
	copy(b[9:], tlv)
	l.pending[seq] = &pending{data: b, sent: time.Now()}
	l.mu.Unlock()
	return seq, l.send(b)
}
func (l *Link) waitACK(ctx context.Context, seq uint16) error {
	for {
		l.mu.Lock()
		_, ok := l.pending[seq]
		l.mu.Unlock()
		if !ok {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-l.done:
			return l.Err()
		case <-l.changed:
		}
	}
}
func (l *Link) readLoop() {
	b := make([]byte, 65536)
	for {
		n, err := l.conn.Read(b)
		if err != nil {
			l.fail(err)
			return
		}
		if n == 0 {
			continue
		}
		data := append([]byte(nil), b[:n]...)
		if l.compression {
			data, err = decompressPacket(data, 65535)
			if err != nil {
				l.fail(fmt.Errorf("decode compressed VPN datagram: %w", err))
				return
			}
		}
		if len(data) == 0 {
			l.fail(errors.New("empty VPN frame"))
			return
		}
		l.mu.Lock()
		l.receivedFrames++
		l.mu.Unlock()
		switch data[0] {
		case 1:
			p := data[1:]
			if len(p) < 20 || p[0]>>4 != 4 || int(binary.BigEndian.Uint16(p[2:4])) != len(p) {
				l.fail(errors.New("invalid incoming IPv4 packet"))
				return
			}
			select {
			case l.packets <- p:
			case <-l.done:
				return
			default:
			} // Datagram queue overflow is packet loss, not unbounded allocation.
		case 2:
			if err = l.receiveControl(data[1:]); err != nil {
				l.fail(err)
				return
			}
		case 4, 20:
			if len(data) < 5 || (l.pingExtended && len(data) < 39) {
				l.fail(errors.New("truncated VPN heartbeat"))
				return
			}
			hold, interval := binary.BigEndian.Uint16(data[1:3]), binary.BigEndian.Uint16(data[3:5])
			if hold < 1 || interval < 1 || interval > hold {
				l.fail(errors.New("invalid VPN heartbeat settings"))
				return
			}
			l.mu.Lock()
			l.lastRecv = time.Now()
			l.heartbeatHold = time.Duration(hold) * time.Second
			l.heartbeatInterval = time.Duration(interval) * time.Second
			if l.pingExtended {
				// The native receive layout deliberately skips bytes 7:15;
				// its server-side counters have different roles from ours.
				l.receiveLoss = binary.BigEndian.Uint64(data[15:23]) - l.receivedFrames
				l.peerReceived = binary.BigEndian.Uint64(data[23:31])
			}
			l.mu.Unlock()
		case 8:
			reason := byte(0)
			if len(data) > 1 {
				reason = data[1]
			}
			l.fail(fmt.Errorf("VPN gateway ended the session (reason %d)", reason))
			return
		default:
			l.fail(fmt.Errorf("unsupported VPN frame type %d", data[0]))
			return
		}
	}
}
func (l *Link) receiveControl(b []byte) error {
	if len(b) < 8 || b[0] != 1 || b[1] > 1 {
		return errors.New("invalid VPN control header")
	}
	n := int(binary.BigEndian.Uint16(b[2:4]))
	if len(b) != 8+n {
		return errors.New("invalid VPN control length")
	}
	if b[1] == 1 {
		ack := binary.BigEndian.Uint16(b[6:8])
		l.mu.Lock()
		delete(l.pending, ack)
		l.mu.Unlock()
		select {
		case l.changed <- struct{}{}:
		default:
		}
		return nil
	}
	seq := binary.BigEndian.Uint16(b[4:6])
	l.mu.Lock()
	expected := l.recvSeq
	// Repeated records are acknowledged without applying their configuration twice.
	if seq != expected {
		l.mu.Unlock()
		if int16(seq-expected) < 0 {
			return l.ack(seq)
		}
		return nil
	}
	if err := l.applyConfiguration(b[8:]); err != nil {
		l.mu.Unlock()
		return err
	}
	l.recvSeq++
	l.mu.Unlock()
	return l.ack(seq)
}
func (l *Link) ack(seq uint16) error {
	b := []byte{2, 1, 1, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(b[7:9], seq)
	return l.send(b)
}

// Caller holds mu. Configuration TLVs use u8 type/u8 length, unlike iptunParam.
func (l *Link) applyConfiguration(raw []byte) error {
	cfg := l.cfg
	cfg.DNS = append([]netip.Addr(nil), l.cfg.DNS...)
	completed := false
	for len(raw) > 0 {
		if len(raw) < 2 || int(raw[1]) > len(raw)-2 {
			return errors.New("truncated VPN configuration TLV")
		}
		typ, n := raw[0], int(raw[1])
		v := raw[2 : 2+n]
		raw = raw[2+n:]
		switch typ {
		case 0x81:
			if len(v) != 8 {
				return errors.New("invalid VPN virtual IP TLV")
			}
			addr := netip.AddrFrom4([4]byte(v[:4]))
			if addr.IsUnspecified() || addr.IsMulticast() {
				return errors.New("invalid VPN assigned IP")
			}
			if l.cfgDone && addr != l.cfg.Address {
				return errors.New("VPN assigned IP changed; reconnect required")
			}
			cfg.Address = addr
			cfg.Netmask = netip.AddrFrom4([4]byte(v[4:8]))
		case 0x82:
			if len(v)%4 != 0 {
				return errors.New("invalid VPN DNS TLV")
			}
			cfg.DNS = nil
			for len(v) > 0 {
				a := netip.AddrFrom4([4]byte(v[:4]))
				if !a.IsUnspecified() {
					cfg.DNS = append(cfg.DNS, a)
				}
				v = v[4:]
			}
		case 0x8d:
			completed = true
		}
	}
	l.cfg = cfg
	if completed && !l.cfgDone {
		l.cfgDone = true
		close(l.ready)
	}
	return nil
}
func (l *Link) maintain() {
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	var lastPing time.Time // The native timer sends its first ping immediately.
	for {
		select {
		case <-l.ctx.Done():
			l.fail(l.ctx.Err())
			return
		case now := <-tick.C:
			l.mu.Lock()
			var retry [][]byte
			var failure error
			for _, p := range l.pending {
				if now.Sub(p.sent) >= time.Second {
					if p.retries >= 10 {
						failure = errors.New("VPN control acknowledgement timed out")
						break
					}
					p.retries++
					p.sent = now
					retry = append(retry, p.data)
				}
			}
			if now.Sub(l.lastRecv) > l.heartbeatHold+10*time.Second && l.receivedFrames == l.receivedAtPing {
				failure = errors.New("VPN heartbeat timed out")
			}
			var ping []byte
			if now.Sub(lastPing) >= l.heartbeatInterval {
				ping = make([]byte, 5)
				ping[0] = 4
				binary.BigEndian.PutUint16(ping[1:3], uint16(l.heartbeatHold/time.Second))
				binary.BigEndian.PutUint16(ping[3:5], uint16(l.heartbeatInterval/time.Second))
				if l.pingExtended {
					ping[0] = 20
					ping = append(ping, make([]byte, 34)...)
				}
				l.receivedAtPing = l.receivedFrames
				lastPing = now
			}
			l.mu.Unlock()
			if failure != nil {
				l.fail(failure)
				return
			}
			for _, b := range retry {
				if err := l.send(b); err != nil {
					l.fail(err)
					return
				}
			}
			if ping != nil {
				if err := l.send(ping); err != nil {
					l.fail(err)
					return
				}
			}
		}
	}
}
