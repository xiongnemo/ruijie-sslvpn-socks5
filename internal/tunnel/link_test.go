package tunnel

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestHeartbeatSeparatesHoldTimeoutAndSendInterval(t *testing.T) {
	link, gateway, _ := connectedLink(t, false)
	gateway.write(t, []byte{4, 0, 5, 0, 1})
	got := gateway.readFrame(t)
	if bytes.Equal(got, []byte{4, 0, 180, 0, 30}) {
		got = gateway.readFrame(t) // A first ping may already have been queued.
	}
	if !bytes.Equal(got, []byte{4, 0, 5, 0, 1}) {
		t.Fatalf("heartbeat must preserve hold=5s and interval=1s: %x", got)
	}
	link.mu.Lock()
	hold, interval := link.heartbeatHold, link.heartbeatInterval
	link.mu.Unlock()
	if hold != 5*time.Second || interval != time.Second {
		t.Fatal("heartbeat timeout and interval confused")
	}
	link.mu.Lock()
	link.lastRecv = time.Now().Add(-16 * time.Second)
	link.mu.Unlock()
	select {
	case <-link.Done():
	case <-time.After(time.Second):
		t.Fatal("heartbeat hold timeout was multiplied by interval")
	}
}

func TestNegotiatedExtendedHeartbeatCounters(t *testing.T) {
	for _, compression := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "compressed"}[compression], func(t *testing.T) {
			client, gateway := datagramPair(t, compression)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan connectResult, 1)
			go func() {
				link, cfg, err := Connect(ctx, client, bytes.Repeat([]byte{0x51}, 32), Options{Compression: compression, ExtendedHeartbeat: true, Timeout: 3 * time.Second})
				result <- connectResult{link, cfg, err}
			}()
			var sent uint64
			var sequence uint16
			read := func() []byte {
				raw := gateway.readFrame(t)
				sent++
				if len(raw) > 0 && raw[0] == 20 {
					if len(raw) != 39 || binary.BigEndian.Uint64(raw[7:15]) != sent || binary.BigEndian.Uint16(raw[5:7]) != sequence {
						t.Fatalf("extended heartbeat send counters mismatch: %x; sent=%d sequence=%d", raw, sent, sequence)
					}
					sequence++
				}
				return raw
			}
			readControl := func() []byte {
				for {
					raw := read()
					if raw[0] != 20 {
						return raw
					}
				}
			}
			if got := readControl(); !bytes.Equal(got, controlFrame(1, append([]byte{1, 32}, bytes.Repeat([]byte{0x51}, 32)...))) {
				t.Fatalf("wrong session request: %x", got)
			}
			gateway.write(t, ackFrame(1))
			if got := readControl(); !bytes.Equal(got, controlFrame(2, []byte{2, 0})) {
				t.Fatalf("wrong configuration request: %x", got)
			}
			gateway.write(t, ackFrame(2))
			gateway.write(t, controlFrame(1, configurationTLVs()))
			if got := readControl(); !bytes.Equal(got, ackFrame(1)) {
				t.Fatalf("wrong configuration ACK: %x", got)
			}
			if connected := awaitConnect(t, result); connected.err != nil {
				t.Fatal(connected.err)
			}
			// The first native ping is immediate, without first receiving one.
			if sequence == 0 {
				if got := read(); got[0] != 20 {
					t.Fatalf("negotiated capability did not select extended ping: %x", got)
				}
			}
			peerPing := make([]byte, 39)
			copy(peerPing, []byte{20, 0, 5, 0, 1, 0, 9})
			binary.BigEndian.PutUint64(peerPing[7:15], 999) // Native skips this slot.
			binary.BigEndian.PutUint64(peerPing[15:23], 150)
			binary.BigEndian.PutUint64(peerPing[23:31], 17)
			gateway.write(t, peerPing)             // Fourth incoming application frame.
			gateway.write(t, controlFrame(2, nil)) // Fifth frame; ACK is a read barrier.
			if got := readControl(); !bytes.Equal(got, ackFrame(2)) {
				t.Fatalf("wrong empty control ACK: %x", got)
			}
			ping := read()
			if ping[0] != 20 || !bytes.Equal(ping[1:5], []byte{0, 5, 0, 1}) || binary.BigEndian.Uint64(ping[15:23]) != 5 || binary.BigEndian.Uint64(ping[23:31]) != 17 || binary.BigEndian.Uint64(ping[31:39]) != 146 {
				t.Fatalf("extended heartbeat receive counters or offsets mismatch: %x", ping)
			}
		})
	}
}

// udpPeer preserves actual datagram boundaries while providing the connected
// net.Conn contract that the production DTLS transport supplies to Link.
type udpPeer struct {
	*net.UDPConn
	remote *net.UDPAddr
}

func (c *udpPeer) Write(data []byte) (int, error) { return c.WriteToUDP(data, c.remote) }
func (c *udpPeer) RemoteAddr() net.Addr           { return c.remote }

type testGateway struct {
	conn        net.Conn
	compression bool
}

func datagramPair(t *testing.T, compression bool) (net.Conn, testGateway) {
	t.Helper()
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close(); server.Close() })
	return client, testGateway{conn: &udpPeer{UDPConn: server, remote: client.LocalAddr().(*net.UDPAddr)}, compression: compression}
}

func (g testGateway) read(t *testing.T) []byte {
	t.Helper()
	for {
		raw := g.readFrame(t)
		if len(raw) > 0 && (raw[0] == 4 || raw[0] == 20) {
			continue
		}
		return raw
	}
}

func (g testGateway) readFrame(t *testing.T) []byte {
	t.Helper()
	g.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buffer := make([]byte, 65536)
	n, err := g.conn.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	raw := buffer[:n]
	if g.compression {
		raw, err = decompressPacket(raw, 65535)
		if err != nil {
			t.Fatal(err)
		}
	}
	return raw
}

func (g testGateway) write(t *testing.T, raw []byte) {
	t.Helper()
	if g.compression {
		var err error
		raw, err = compressPacket(raw)
		if err != nil {
			t.Fatal(err)
		}
	}
	g.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if n, err := g.conn.Write(raw); err != nil || n != len(raw) {
		t.Fatalf("gateway datagram write: %d/%d bytes, %v", n, len(raw), err)
	}
}

func controlFrame(seq uint16, tlvs []byte) []byte {
	raw := make([]byte, 9+len(tlvs))
	raw[0], raw[1] = 2, 1
	binary.BigEndian.PutUint16(raw[3:5], uint16(len(tlvs)))
	binary.BigEndian.PutUint16(raw[5:7], seq)
	copy(raw[9:], tlvs)
	return raw
}

func ackFrame(seq uint16) []byte {
	raw := []byte{2, 1, 1, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(raw[7:9], seq)
	return raw
}

func configurationTLVs() []byte {
	return []byte{
		0x81, 8, 10, 23, 0, 9, 255, 255, 255, 0,
		0x82, 4, 10, 23, 0, 53,
		0x8d, 0,
	}
}

func testIPv4Packet() []byte {
	packet := make([]byte, 20+23)
	packet[0], packet[8], packet[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[12:16], []byte{10, 23, 0, 9})
	copy(packet[16:20], []byte{10, 23, 0, 20})
	copy(packet[20:], []byte("binary VPN payload\x00\xff\x01\x02\x03"))
	return packet
}

type connectResult struct {
	link *Link
	cfg  Configuration
	err  error
}

func beginConnect(t *testing.T, ctx context.Context, client net.Conn, compression bool, timeout time.Duration) <-chan connectResult {
	t.Helper()
	child, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	result := make(chan connectResult, 1)
	go func() {
		link, cfg, err := Connect(child, client, bytes.Repeat([]byte{0x51}, 32), Options{Compression: compression, Timeout: timeout})
		result <- connectResult{link, cfg, err}
	}()
	return result
}

func awaitConnect(t *testing.T, result <-chan connectResult) connectResult {
	t.Helper()
	select {
	case connected := <-result:
		if connected.link != nil {
			t.Cleanup(func() { connected.link.Close() })
		}
		return connected
	case <-time.After(5 * time.Second):
		t.Fatal("Connect did not finish")
		return connectResult{}
	}
}

func negotiateRequests(t *testing.T, gateway testGateway) {
	t.Helper()
	sessionTLV := append([]byte{1, 32}, bytes.Repeat([]byte{0x51}, 32)...)
	got := gateway.read(t)
	if len(got) < 9 {
		t.Fatalf("truncated session request: %x", got)
	}
	firstSeq := binary.BigEndian.Uint16(got[5:7])
	if firstSeq != 1 {
		t.Fatalf("first outbound sequence = %d, want native sequence 1", firstSeq)
	}
	if !bytes.Equal(got, controlFrame(firstSeq, sessionTLV)) {
		t.Fatalf("wrong session request frame: %x", got)
	}
	gateway.write(t, ackFrame(firstSeq))
	if got := gateway.read(t); !bytes.Equal(got, controlFrame(firstSeq+1, []byte{2, 0})) {
		t.Fatalf("wrong configuration request frame: %x", got)
	}
	gateway.write(t, ackFrame(firstSeq+1))
}

func connectedLink(t *testing.T, compression bool) (*Link, testGateway, Configuration) {
	t.Helper()
	client, gateway := datagramPair(t, compression)
	result := beginConnect(t, context.Background(), client, compression, 3*time.Second)
	negotiateRequests(t, gateway)
	gateway.write(t, controlFrame(1, configurationTLVs()))
	if got := gateway.read(t); !bytes.Equal(got, ackFrame(1)) {
		t.Fatalf("wrong server configuration ACK: %x", got)
	}
	connected := awaitConnect(t, result)
	if connected.err != nil {
		t.Fatal(connected.err)
	}
	return connected.link, gateway, connected.cfg
}

func TestConnectNegotiatesSessionConfigurationAndEchoesRawIP(t *testing.T) {
	for _, compression := range []bool{false, true} {
		name := "uncompressed"
		if compression {
			name = "compressed"
		}
		t.Run(name, func(t *testing.T) {
			link, gateway, cfg := connectedLink(t, compression)
			if cfg.Address != netip.MustParseAddr("10.23.0.9") || cfg.Netmask != netip.MustParseAddr("255.255.255.0") || len(cfg.DNS) != 1 || cfg.DNS[0] != netip.MustParseAddr("10.23.0.53") || cfg.MTU != 1400 {
				t.Fatalf("incorrect negotiated configuration: %+v", cfg)
			}
			packet := testIPv4Packet()
			if err := link.WritePacket(packet); err != nil {
				t.Fatal(err)
			}
			wire := gateway.read(t)
			if !bytes.Equal(wire, append([]byte{1}, packet...)) {
				t.Fatalf("wrong raw-IP framing: %x", wire)
			}
			gateway.write(t, wire)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			got, err := link.ReadPacket(ctx)
			if err != nil || !bytes.Equal(got, packet) {
				t.Fatalf("raw-IP echo mismatch: %x, %v", got, err)
			}
		})
	}
}

func TestDuplicateControlIsReACKedWithoutApplyingConfiguration(t *testing.T) {
	link, gateway, cfg := connectedLink(t, false)
	duplicate := configurationTLVs()
	duplicate[5] = 99 // A new address would fail if the duplicate were reapplied.
	duplicate[15] = 99
	gateway.write(t, controlFrame(1, duplicate))
	if got := gateway.read(t); !bytes.Equal(got, ackFrame(1)) {
		t.Fatalf("duplicate configuration was not reACKed: %x", got)
	}
	link.mu.Lock()
	address, dns, recvSeq := link.cfg.Address, append([]netip.Addr(nil), link.cfg.DNS...), link.recvSeq
	link.mu.Unlock()
	if address != cfg.Address || len(dns) != 1 || dns[0] != cfg.DNS[0] || recvSeq != 2 {
		t.Fatal("duplicate control changed configuration or sequence")
	}
	select {
	case <-link.Done():
		t.Fatalf("duplicate ended tunnel: %v", link.Err())
	default:
	}
}

func TestControlSequenceOrderingAndWraparound(t *testing.T) {
	link, gateway, _ := connectedLink(t, false)
	// A future sequence must not be applied or ACKed; the next expected
	// message gets the first ACK, and retrying the future one then succeeds.
	gateway.write(t, controlFrame(3, []byte{0x82, 4, 10, 23, 0, 99}))
	gateway.write(t, controlFrame(2, []byte{0x82, 4, 10, 23, 0, 54}))
	if got := gateway.read(t); !bytes.Equal(got, ackFrame(2)) {
		t.Fatalf("future control sequence was ACKed prematurely: %x", got)
	}
	gateway.write(t, controlFrame(3, []byte{0x82, 4, 10, 23, 0, 55}))
	if got := gateway.read(t); !bytes.Equal(got, ackFrame(3)) {
		t.Fatalf("retried in-order control was not ACKed: %x", got)
	}
	link.mu.Lock()
	if link.cfg.DNS[0] != netip.MustParseAddr("10.23.0.55") {
		t.Error("in-order configuration was not applied")
	}
	link.recvSeq = 65535
	link.mu.Unlock()
	for _, seq := range []uint16{65535, 0, 65535} {
		gateway.write(t, controlFrame(seq, nil))
		if got := gateway.read(t); !bytes.Equal(got, ackFrame(seq)) {
			t.Fatalf("sequence %d did not wrap/reACK correctly: %x", seq, got)
		}
	}
}

func TestControlRetransmissionPreservesSequenceAndPayload(t *testing.T) {
	client, gateway := datagramPair(t, false)
	result := beginConnect(t, context.Background(), client, false, 4*time.Second)
	first := gateway.read(t)
	if len(first) < 9 {
		t.Fatalf("truncated session request: %x", first)
	}
	firstSeq := binary.BigEndian.Uint16(first[5:7])
	retry := gateway.read(t) // Deliberately drop the first ACK; retry is about 1 s.
	if !bytes.Equal(first, retry) || binary.BigEndian.Uint16(retry[5:7]) != firstSeq {
		t.Fatal("control retransmission changed its sequence or payload")
	}
	gateway.write(t, ackFrame(firstSeq))
	if got := gateway.read(t); !bytes.Equal(got, controlFrame(firstSeq+1, []byte{2, 0})) {
		t.Fatalf("wrong next sequence after retry: %x", got)
	}
	gateway.write(t, ackFrame(firstSeq+1))
	gateway.write(t, controlFrame(1, configurationTLVs()))
	if got := gateway.read(t); !bytes.Equal(got, ackFrame(1)) {
		t.Fatalf("wrong configuration ACK: %x", got)
	}
	if connected := awaitConnect(t, result); connected.err != nil {
		t.Fatal(connected.err)
	}
}

func TestConnectCancellationAndTimeoutCloseTransport(t *testing.T) {
	for _, stage := range []string{"session ACK", "configuration", "config done marker", "timeout"} {
		t.Run(stage, func(t *testing.T) {
			client, gateway := datagramPair(t, false)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			timeout := 3 * time.Second
			if stage == "timeout" {
				timeout = 60 * time.Millisecond
			}
			result := beginConnect(t, ctx, client, false, timeout)
			if stage == "configuration" || stage == "config done marker" {
				negotiateRequests(t, gateway)
				if stage == "config done marker" {
					gateway.write(t, controlFrame(1, configurationTLVs()[:16]))
					if got := gateway.read(t); !bytes.Equal(got, ackFrame(1)) {
						t.Fatalf("configuration fragment was not ACKed: %x", got)
					}
				}
			} else {
				gateway.read(t)
			}
			if stage != "timeout" {
				cancel()
			}
			connected := awaitConnect(t, result)
			want := context.Canceled
			if stage == "timeout" {
				want = context.DeadlineExceeded
			}
			if connected.link != nil || !errors.Is(connected.err, want) {
				t.Fatalf("unfinished negotiation returned link=%v error=%v", connected.link, connected.err)
			}
			if _, err := client.Write([]byte{1}); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("failed negotiation left transport open: %v", err)
			}
		})
	}
}

func TestMalformedFramesCloseEstablishedLink(t *testing.T) {
	for _, test := range []struct {
		name string
		raw  []byte
	}{
		{"short control header", []byte{2, 1}},
		{"wrong control version", []byte{2, 2, 0, 0, 0, 0, 1, 0, 0}},
		{"unknown control flags", []byte{2, 1, 2, 0, 0, 0, 1, 0, 0}},
		{"control length mismatch", []byte{2, 1, 0, 0, 2, 0, 1, 0, 0}},
		{"truncated configuration TLV", controlFrame(2, []byte{0x81, 8, 10, 23})},
		{"invalid address TLV size", controlFrame(2, []byte{0x81, 4, 10, 23, 0, 9})},
		{"assigned address changed", controlFrame(2, []byte{0x81, 8, 10, 23, 0, 99, 255, 255, 255, 0})},
		{"invalid DNS TLV size", controlFrame(2, []byte{0x82, 3, 10, 23, 0})},
		{"short IPv4 packet", []byte{1, 0x45}},
		{"invalid IPv4 length", append([]byte{1}, make([]byte, 20)...)},
		{"short heartbeat", []byte{4, 0, 1}},
		{"zero heartbeat period", []byte{4, 0, 0, 0, 3}},
		{"zero heartbeat limit", []byte{4, 0, 1, 0, 0}},
		{"unsupported frame type", []byte{99}},
		{"session termination", []byte{8, 4}},
	} {
		t.Run(test.name, func(t *testing.T) {
			link, gateway, _ := connectedLink(t, false)
			gateway.write(t, test.raw)
			select {
			case <-link.Done():
				if link.Err() == nil {
					t.Fatal("malformed frame closed link without an error")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("malformed frame left tunnel running")
			}
		})
	}
}

func TestInvalidCompletedConfigurationDoesNotSucceed(t *testing.T) {
	for _, test := range []struct {
		name string
		tlvs []byte
	}{
		{"missing assigned address", []byte{0x82, 4, 10, 23, 0, 53, 0x8d, 0}},
		{"unspecified assigned address", []byte{0x81, 8, 0, 0, 0, 0, 255, 255, 255, 0, 0x8d, 0}},
		{"multicast assigned address", []byte{0x81, 8, 224, 0, 0, 1, 255, 255, 255, 0, 0x8d, 0}},
		{"malformed TLV after done", append(configurationTLVs(), 0x81)},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, gateway := datagramPair(t, false)
			result := beginConnect(t, context.Background(), client, false, 3*time.Second)
			negotiateRequests(t, gateway)
			gateway.write(t, controlFrame(1, test.tlvs))
			connected := awaitConnect(t, result)
			if connected.err == nil || connected.link != nil {
				t.Fatal("invalid completed configuration was reported as a successful connection")
			}
		})
	}
}

func TestLinkConcurrentReadWriteAndClose(t *testing.T) {
	link, gateway, _ := connectedLink(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var workers sync.WaitGroup
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range 16 {
				if err := link.WritePacket(testIPv4Packet()); err != nil {
					return
				}
			}
		}()
	}
	for range 4 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for {
				if _, err := link.ReadPacket(ctx); err != nil {
					return
				}
			}
		}()
	}
	gateway.write(t, append([]byte{1}, testIPv4Packet()...))
	for range 4 {
		workers.Add(1)
		go func() { defer workers.Done(); link.Close() }()
	}
	finished := make(chan struct{})
	go func() { workers.Wait(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent Close did not release readers and writers")
	}
	if !errors.Is(link.Err(), net.ErrClosed) {
		t.Fatalf("unexpected close error: %v", link.Err())
	}
}
