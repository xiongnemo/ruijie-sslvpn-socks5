package tunnel

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Parameters is the binary (type:u8,length:be16,value) iptunParam document.
// See native function 1800ca6e0, bound to analysis/artifact-hashes.json.
type Parameters struct {
	Endpoint    netip.AddrPort
	SessionID   []byte
	Secret      []byte
	Timeout     time.Duration
	Compression bool
	DTLS12      bool
}

func (p Parameters) String() string { return "VPN tunnel parameters (session secrets redacted)" }

func ParseParameters(raw []byte) (Parameters, error) {
	var p Parameters
	var host, port string
	seen := make(map[byte]bool)
	for len(raw) > 0 {
		if len(raw) < 3 {
			return p, errors.New("truncated tunnel parameter header")
		}
		typ := raw[0]
		n := int(binary.BigEndian.Uint16(raw[1:3]))
		raw = raw[3:]
		if n > len(raw) {
			return p, errors.New("truncated tunnel parameter value")
		}
		v := raw[:n]
		raw = raw[n:]
		if seen[typ] {
			return p, errors.New("duplicate tunnel parameter")
		}
		seen[typ] = true
		switch typ {
		case 1:
			host = strings.TrimSpace(string(v))
		case 2:
			port = strings.TrimSpace(string(v))
		case 3:
			p.SessionID = append([]byte(nil), v...)
		case 4:
			x, err := strconv.Atoi(strings.TrimSpace(string(v)))
			if err != nil || x < 0 || x > 86400 {
				return p, errors.New("invalid tunnel timeout")
			}
			p.Timeout = time.Duration(x) * time.Second
		case 5:
			mode := strings.TrimSpace(string(v))
			if mode != "0" && mode != "1" {
				return p, errors.New("invalid tunnel compression mode")
			}
			p.Compression = mode == "1"
		case 6:
			p.Secret = append([]byte(nil), v...)
		case 7:
			p.DTLS12 = strings.Contains(strings.ToLower(string(v)), "dtls1.2")
		default:
			return p, errors.New("unknown tunnel parameter type")
		}
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.Is4() {
		return p, errors.New("gateway supplied an invalid IPv4 tunnel endpoint")
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return p, errors.New("gateway supplied an invalid tunnel port")
	}
	p.Endpoint = netip.AddrPortFrom(ip, uint16(n))
	if len(p.SessionID) != 32 || len(p.Secret) != 16 {
		return p, errors.New("gateway supplied invalid tunnel session key lengths")
	}
	return p, nil
}
