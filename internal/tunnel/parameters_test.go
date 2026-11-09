package tunnel

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func parameter(typ byte, value []byte) []byte {
	raw := make([]byte, 3+len(value))
	raw[0] = typ
	binary.BigEndian.PutUint16(raw[1:3], uint16(len(value)))
	copy(raw[3:], value)
	return raw
}

func validParameterDocument() []byte {
	var document []byte
	for _, field := range []struct {
		typ   byte
		value []byte
	}{
		{1, []byte("192.0.2.7")},
		{2, []byte("10443")},
		{3, bytes.Repeat([]byte{0xab}, 32)},
		{4, []byte("300")},
		{5, []byte("1")},
		{6, bytes.Repeat([]byte{0xcd}, 16)},
		{7, []byte("DTLS1.2")},
	} {
		document = append(document, parameter(field.typ, field.value)...)
	}
	return document
}

func replaceParameter(document []byte, typ byte, value []byte) []byte {
	var out []byte
	for len(document) != 0 {
		n := 3 + int(binary.BigEndian.Uint16(document[1:3]))
		if document[0] == typ {
			out = append(out, parameter(typ, value)...)
		} else {
			out = append(out, document[:n]...)
		}
		document = document[n:]
	}
	return out
}

func TestParseParametersPreservesBinaryKeysAndDoesNotAliasInput(t *testing.T) {
	raw := validParameterDocument()
	p, err := ParseParameters(raw)
	if err != nil {
		t.Fatal(err)
	}
	if p.Endpoint != netip.MustParseAddrPort("192.0.2.7:10443") || p.Timeout != 300*time.Second || !p.Compression || !p.DTLS12 || !bytes.Equal(p.SessionID, bytes.Repeat([]byte{0xab}, 32)) || !bytes.Equal(p.Secret, bytes.Repeat([]byte{0xcd}, 16)) {
		t.Fatal("decoded parameters do not match the wire document")
	}
	clear(raw)
	if p.SessionID[0] != 0xab || p.Secret[0] != 0xcd {
		t.Fatal("session keys alias the caller's input buffer")
	}
	for _, format := range []string{"%v", "%+v", "%s"} {
		text := fmt.Sprintf(format, p)
		if !strings.Contains(text, "redacted") || strings.Contains(text, "171 171") || strings.Contains(text, "205 205") {
			t.Fatal("formatting tunnel parameters could expose session secrets")
		}
	}
}

func TestParseParametersRejectsMalformedOrAmbiguousDocuments(t *testing.T) {
	valid := validParameterDocument()
	for _, test := range []struct {
		name string
		raw  []byte
	}{
		{"empty", nil},
		{"header truncated", []byte{1, 0}},
		{"value truncated", []byte{1, 0, 10, 'a'}},
		{"duplicate endpoint", append(append([]byte(nil), valid...), parameter(1, []byte("192.0.2.8"))...)},
		{"unknown type", append(append([]byte(nil), valid...), parameter(99, nil)...)},
		{"hostname endpoint", replaceParameter(valid, 1, []byte("gateway.test"))},
		{"IPv6 endpoint", replaceParameter(valid, 1, []byte("2001:db8::7"))},
		{"endpoint internal whitespace", replaceParameter(valid, 1, []byte("192.0. 2.7"))},
		{"port zero", replaceParameter(valid, 2, []byte("0"))},
		{"port overflow", replaceParameter(valid, 2, []byte("65536"))},
		{"service name port", replaceParameter(valid, 2, []byte("https"))},
		{"short session ID", replaceParameter(valid, 3, make([]byte, 31))},
		{"long session ID", replaceParameter(valid, 3, make([]byte, 33))},
		{"negative timeout", replaceParameter(valid, 4, []byte("-1"))},
		{"large timeout", replaceParameter(valid, 4, []byte("86401"))},
		{"text timeout", replaceParameter(valid, 4, []byte("30s"))},
		{"unsupported compression", replaceParameter(valid, 5, []byte("2"))},
		{"short secret", replaceParameter(valid, 6, make([]byte, 15))},
		{"long secret", replaceParameter(valid, 6, make([]byte, 17))},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseParameters(test.raw); err == nil {
				t.Fatal("malformed tunnel parameter document was accepted")
			}
		})
	}
}

func TestGatewayPaddedTextParametersPreserveBinaryKeys(t *testing.T) {
	// The real gateway returns a trailing space on the IP and a leading
	// space on the port. Only textual TLVs may be normalized.
	raw := replaceParameter(validParameterDocument(), 1, []byte("192.0.2.7 "))
	raw = replaceParameter(raw, 2, []byte(" 8443"))
	raw = replaceParameter(raw, 4, []byte(" 30 "))
	raw = replaceParameter(raw, 5, []byte(" 0 "))
	session := append([]byte(" "), bytes.Repeat([]byte{0xab}, 30)...)
	session = append(session, ' ')
	secret := append([]byte(" "), bytes.Repeat([]byte{0xcd}, 14)...)
	secret = append(secret, ' ')
	raw = replaceParameter(raw, 3, session)
	raw = replaceParameter(raw, 6, secret)
	raw = replaceParameter(raw, 7, []byte("dtls1.0;dtls1.2"))
	p, err := ParseParameters(raw)
	if err != nil {
		t.Fatal(err)
	}
	if p.Endpoint != netip.MustParseAddrPort("192.0.2.7:8443") || p.Timeout != 30*time.Second || p.Compression || !p.DTLS12 || !bytes.Equal(p.SessionID, session) || !bytes.Equal(p.Secret, secret) {
		t.Fatal("padded text was not normalized or binary credentials were changed")
	}
}

func TestParseParametersCompressionAndVersionModes(t *testing.T) {
	raw := replaceParameter(validParameterDocument(), 5, []byte("0"))
	raw = replaceParameter(raw, 7, []byte("DTLS1.0"))
	p, err := ParseParameters(raw)
	if err != nil || p.Compression || p.DTLS12 {
		t.Fatal("legacy DTLS/uncompressed mode parsed incorrectly")
	}
}
