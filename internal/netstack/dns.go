package netstack

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/idna"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

func dnsError(name, message string, notFound bool) error {
	return &net.DNSError{Err: message, Name: name, IsNotFound: notFound}
}

// lookupIPv4 intentionally does not use net.DefaultResolver or net.Resolver,
// including on Windows, where they can invoke the host's DNS APIs.
func (n *Network) lookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	if len(n.dns) == 0 {
		return nil, dnsError(host, "VPN supplied no IPv4 DNS servers; configure DNS servers or use an IP address", false)
	}
	ascii, err := idna.Lookup.ToASCII(strings.TrimSuffix(host, "."))
	if err != nil || ascii == "" {
		return nil, dnsError(host, "invalid DNS name", false)
	}
	name, err := dnsmessage.NewName(ascii + ".")
	if err != nil {
		return nil, dnsError(host, "invalid DNS name", false)
	}
	for depth := 0; depth < 8; depth++ {
		var token [2]byte
		if _, err := rand.Read(token[:]); err != nil {
			return nil, err
		}
		id := binary.BigEndian.Uint16(token[:])
		q := dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
		query, err := (&dnsmessage.Message{Header: dnsmessage.Header{ID: id, RecursionDesired: true}, Questions: []dnsmessage.Question{q}}).Pack()
		if err != nil {
			return nil, err
		}
		var response dnsmessage.Message
		var last error
		found := false
		for attempt := 0; attempt < 2 && !found; attempt++ {
			for _, server := range n.dns {
				data, err := n.exchangeDNS(ctx, server, query, id, q)
				if err != nil {
					last = err
					if ctx.Err() != nil {
						return nil, ctx.Err()
					}
					continue
				}
				if err := response.Unpack(data); err != nil {
					last = err
					continue
				}
				if response.RCode == dnsmessage.RCodeNameError {
					return nil, dnsError(host, "no such host", true)
				}
				if response.RCode != dnsmessage.RCodeSuccess {
					last = fmt.Errorf("VPN DNS returned %s", response.RCode)
					continue
				}
				found = true
				break
			}
		}
		if !found {
			return nil, dnsError(host, fmt.Sprintf("VPN DNS query failed: %v", last), false)
		}
		// Only A records reachable through the question's CNAME chain are valid.
		current := name
		seen := make(map[string]bool)
		for hop := 0; hop < 8; hop++ {
			key := strings.ToLower(current.String())
			if seen[key] {
				return nil, dnsError(host, "DNS CNAME loop", false)
			}
			seen[key] = true
			var addresses []netip.Addr
			for _, answer := range response.Answers {
				if answer.Header.Class != dnsmessage.ClassINET || !strings.EqualFold(answer.Header.Name.String(), current.String()) {
					continue
				}
				if a, ok := answer.Body.(*dnsmessage.AResource); ok {
					addresses = append(addresses, netip.AddrFrom4(a.A))
				}
			}
			if len(addresses) > 0 {
				return addresses, nil
			}
			next := current
			for _, answer := range response.Answers {
				if answer.Header.Class == dnsmessage.ClassINET && strings.EqualFold(answer.Header.Name.String(), current.String()) {
					if a, ok := answer.Body.(*dnsmessage.CNAMEResource); ok {
						next = a.CNAME
						break
					}
				}
			}
			if next == current {
				break
			}
			current = next
		}
		if current == name {
			return nil, dnsError(host, "no IPv4 address records", true)
		}
		name = current
	}
	return nil, dnsError(host, "too many DNS CNAME redirects", false)
}

func validDNSResponse(data []byte, id uint16, question dnsmessage.Question) (bool, bool) {
	var parser dnsmessage.Parser
	h, err := parser.Start(data)
	if err != nil || h.ID != id || !h.Response || h.OpCode != 0 {
		return false, false
	}
	q, err := parser.Question()
	if err != nil || q.Type != question.Type || q.Class != question.Class || !strings.EqualFold(q.Name.String(), question.Name.String()) {
		return false, false
	}
	if _, err := parser.Question(); !errors.Is(err, dnsmessage.ErrSectionDone) {
		return false, false
	}
	return true, h.Truncated
}

func (n *Network) exchangeDNS(ctx context.Context, server netip.Addr, query []byte, id uint16, q dnsmessage.Question) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	remote := fullAddress(server, 53)
	c, err := gonet.DialUDP(n.stack, nil, &remote, ipv4.ProtocolNumber)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	_ = c.SetDeadline(deadline)
	if _, err = c.Write(query); err != nil {
		return nil, err
	}
	response := make([]byte, 65535)
	for {
		count, err := c.Read(response)
		if err != nil {
			return nil, err
		}
		valid, truncated := validDNSResponse(response[:count], id, q)
		if !valid {
			continue
		}
		if !truncated {
			return response[:count], nil
		}
		break
	}
	// RFC 7766 fallback remains inside the same userspace stack.
	tcp, err := gonet.DialContextTCP(ctx, n.stack, remote, ipv4.ProtocolNumber)
	if err != nil {
		return nil, err
	}
	defer tcp.Close()
	stopTCP := context.AfterFunc(ctx, func() { _ = tcp.Close() })
	defer stopTCP()
	_ = tcp.SetDeadline(deadline)
	message := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(message, uint16(len(query)))
	copy(message[2:], query)
	if _, err = io.Copy(tcp, bytes.NewReader(message)); err != nil {
		return nil, err
	}
	var length [2]byte
	if _, err = io.ReadFull(tcp, length[:]); err != nil {
		return nil, err
	}
	response = make([]byte, int(binary.BigEndian.Uint16(length[:])))
	if _, err = io.ReadFull(tcp, response); err != nil {
		return nil, err
	}
	valid, truncated := validDNSResponse(response, id, q)
	if !valid || truncated {
		return nil, errors.New("invalid VPN DNS TCP response")
	}
	return response, nil
}
