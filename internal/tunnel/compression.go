package tunnel

import (
	"encoding/binary"
	"errors"
)

// The native FUN_1800b6de0 compresses each entire application datagram using
// LZO1X before SSL_write. This implementation emits LZO1X v0 literal streams
// and accepts all v0 back-reference instruction forms. It deliberately does
// not use a decompressor whose output-size argument is only an allocation hint.
// Bitstream reference: https://www.kernel.org/doc/html/latest/staging/lzo.html
const maxLZOPacket = 65535

var (
	errLZOTruncated = errors.New("truncated LZO packet")
	errLZOTooLarge  = errors.New("LZO packet exceeds output limit")
	errLZOMatch     = errors.New("invalid LZO back-reference")
)

func compressPacket(packet []byte) ([]byte, error) {
	if len(packet) > maxLZOPacket {
		return nil, errLZOTooLarge
	}
	// Sending only literals is wire-compatible with LZO1X-1. Its bounded
	// expansion is preferable to leaving negotiated compression unsupported.
	result := make([]byte, 0, len(packet)+len(packet)/255+5)
	n := len(packet)
	switch {
	case n == 0:
	case n <= 238:
		result = append(result, byte(n+17))
	default:
		result = append(result, 0)
		rest := n - 18
		for rest > 255 {
			result = append(result, 0)
			rest -= 255
		}
		result = append(result, byte(rest))
	}
	result = append(result, packet...)
	result = append(result, 17, 0, 0)
	if len(result) > maxLZOPacket {
		return nil, errLZOTooLarge
	}
	return result, nil
}

func decompressPacket(packet []byte, max int) ([]byte, error) {
	if max < 0 || max > maxLZOPacket {
		return nil, errors.New("LZO output limit must be 0..65535")
	}
	if len(packet) > maxLZOPacket {
		return nil, errLZOTooLarge
	}
	d := lzoPacketDecoder{source: packet, limit: max, output: make([]byte, 0, min(max, 1500))}
	if len(packet) == 0 {
		return nil, errLZOTruncated
	}
	state := 0
	if packet[0] > 17 {
		d.pos = 1
		n := int(packet[0]) - 17
		if err := d.literals(n); err != nil {
			return nil, err
		}
		state = n
		if state >= 4 {
			state = 4
		}
	}
	for {
		op, err := d.byte()
		if err != nil {
			return nil, err
		}
		code := int(op)
		if code < 16 && state == 0 {
			length, err := d.length(code, 15)
			if err != nil {
				return nil, err
			}
			if err = d.literals(length + 3); err != nil {
				return nil, err
			}
			state = 4
			continue
		}
		var length, distance, tail int
		switch {
		case code < 16:
			more, err := d.byte()
			if err != nil {
				return nil, err
			}
			distance = 1 + (code >> 2) + (int(more) << 2)
			length = 2
			if state == 4 {
				distance += 2048
				length = 3
			}
			tail = code & 3
		case code >= 64:
			more, err := d.byte()
			if err != nil {
				return nil, err
			}
			length = (code >> 5) + 1
			distance = 1 + ((code >> 2) & 7) + (int(more) << 3)
			tail = code & 3
		case code >= 32:
			length, err = d.length(code&31, 31)
			if err != nil {
				return nil, err
			}
			length += 2
			offset, err := d.word()
			if err != nil {
				return nil, err
			}
			distance = 1 + (offset >> 2)
			tail = offset & 3
		default: // 16..31: the long-distance family also carries the EOF marker.
			length, err = d.length(code&7, 7)
			if err != nil {
				return nil, err
			}
			length += 2
			offset, err := d.word()
			if err != nil {
				return nil, err
			}
			distance = ((code & 8) << 11) + (offset >> 2)
			if distance == 0 {
				if length != 3 || offset != 0 {
					return nil, errors.New("invalid LZO end marker")
				}
				if d.pos != len(packet) {
					return nil, errors.New("trailing data after LZO packet")
				}
				return d.output, nil
			}
			distance += 16384
			tail = offset & 3
		}
		if err = d.match(distance, length); err != nil {
			return nil, err
		}
		if err = d.literals(tail); err != nil {
			return nil, err
		}
		state = tail
	}
}

type lzoPacketDecoder struct {
	source []byte
	pos    int
	output []byte
	limit  int
}

func (d *lzoPacketDecoder) byte() (byte, error) {
	if d.pos >= len(d.source) {
		return 0, errLZOTruncated
	}
	b := d.source[d.pos]
	d.pos++
	return b, nil
}
func (d *lzoPacketDecoder) word() (int, error) {
	if len(d.source)-d.pos < 2 {
		return 0, errLZOTruncated
	}
	v := int(binary.LittleEndian.Uint16(d.source[d.pos:]))
	d.pos += 2
	return v, nil
}
func (d *lzoPacketDecoder) length(short, base int) (int, error) {
	if short != 0 {
		return short, nil
	}
	n := base
	for {
		b, err := d.byte()
		if err != nil {
			return 0, err
		}
		if b != 0 {
			if n > d.limit-int(b) {
				return 0, errLZOTooLarge
			}
			return n + int(b), nil
		}
		if n > d.limit-255 {
			return 0, errLZOTooLarge
		}
		n += 255
	}
}
func (d *lzoPacketDecoder) literals(n int) error {
	if n < 0 || n > d.limit-len(d.output) {
		return errLZOTooLarge
	}
	if n > len(d.source)-d.pos {
		return errLZOTruncated
	}
	d.output = append(d.output, d.source[d.pos:d.pos+n]...)
	d.pos += n
	return nil
}
func (d *lzoPacketDecoder) match(distance, n int) error {
	if distance <= 0 || distance > len(d.output) {
		return errLZOMatch
	}
	if n < 0 || n > d.limit-len(d.output) {
		return errLZOTooLarge
	}
	// A reference may overlap its destination, e.g. a distance of one repeats
	// the most recent byte. Copy sequentially instead of using Go's copy.
	from := len(d.output) - distance
	for i := 0; i < n; i++ {
		d.output = append(d.output, d.output[from+i])
	}
	return nil
}
