package tunnel

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func TestLZOIndependentBusyBoxVector(t *testing.T) {
	// LZO payload extracted from BusyBox lzop 1.38.0's independently produced
	// .lzo stream for the 1000-byte input below, with its file header removed.
	compressed, err := hex.DecodeString("0b68656c6c6f206c7a6f2068656c6c20000000bc2400110000")
	if err != nil {
		t.Fatal(err)
	}
	want := bytes.Repeat([]byte("hello lzo "), 100)
	got, err := decompressPacket(compressed, len(want))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("output differs from independently compressed data")
	}
	if _, err = decompressPacket(compressed, len(want)-1); !errors.Is(err, errLZOTooLarge) {
		t.Fatalf("did not enforce exact output limit: %v", err)
	}
}

func TestLZOInstructionFamilies(t *testing.T) {
	tests := []struct {
		name       string
		compressed []byte
		want       string
	}{
		{"short match", []byte{21, 'a', 'b', 'c', 'd', 64, 0, 17, 0, 0}, "abcdddd"},
		{"long short-distance match", []byte{21, 'a', 'b', 'c', 'd', 128, 0, 17, 0, 0}, "abcdddddd"},
		{"medium match", []byte{21, 'a', 'b', 'c', 'd', 33, 0, 0, 17, 0, 0}, "abcdddd"},
		{"extended medium match", []byte{21, 'a', 'b', 'c', 'd', 32, 2, 0, 0, 17, 0, 0}, "abcd" + string(bytes.Repeat([]byte{'d'}, 35))},
		{"two-byte match after literal tail", []byte{21, 'a', 'b', 'c', 'd', 65, 0, 'e', 0, 0, 17, 0, 0}, "abcddddeee"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decompressPacket(tt.compressed, maxLZOPacket)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
	for _, tt := range []struct {
		name        string
		literalLen  int
		instruction []byte
		distance    int
	}{
		{"three-byte first-literal match", 2049, []byte{0, 0}, 2049},
		{"long-distance low", 20000, []byte{17, 4, 0}, 16385},
		{"long-distance high", 40000, []byte{25, 4, 0}, 32769},
	} {
		t.Run(tt.name, func(t *testing.T) {
			prefix := make([]byte, tt.literalLen)
			for i := range prefix {
				prefix[i] = byte(i)
			}
			encoded, err := compressPacket(prefix)
			if err != nil {
				t.Fatal(err)
			}
			encoded = append(encoded[:len(encoded)-3], tt.instruction...)
			encoded = append(encoded, 17, 0, 0)
			got, err := decompressPacket(encoded, maxLZOPacket)
			if err != nil {
				t.Fatal(err)
			}
			want := append(append([]byte(nil), prefix...), prefix[len(prefix)-tt.distance:len(prefix)-tt.distance+3]...)
			if !bytes.Equal(got, want) {
				t.Fatal("long-distance instruction differs")
			}
		})
	}
}

func TestLZOLiteralBoundaries(t *testing.T) {
	for _, n := range []int{0, 1, 2, 3, 4, 17, 18, 237, 238, 239, 272, 273, 274, 528, 529, 1500, 32000, 65000} {
		packet := make([]byte, n)
		for i := range packet {
			packet[i] = byte(i * 73)
		}
		compressed, err := compressPacket(packet)
		if err != nil {
			t.Fatalf("size %d: %v", n, err)
		}
		got, err := decompressPacket(compressed, n)
		if err != nil {
			t.Fatalf("size %d: %v", n, err)
		}
		if !bytes.Equal(got, packet) {
			t.Fatalf("literal boundary %d differs", n)
		}
	}
}

func TestLZORejectsMalformedAndOversizedPackets(t *testing.T) {
	cases := [][]byte{nil, {}, {18}, {18, 'a'}, {17, 0}, {17, 0, 0, 0}, {18, 0, 0}, {18, 'a', 64}, {18, 'a', 64, 1}, {21, 'a', 'b', 'c', 'd', 0, 255}, {18, 0, 16, 0, 0, 0}, {18, 0, 18, 0, 0}}
	for _, input := range cases {
		if _, err := decompressPacket(input, 65535); err == nil {
			t.Errorf("accepted malformed input %x", input)
		}
	}
	if _, err := decompressPacket([]byte{17, 0, 0}, 65536); err == nil {
		t.Fatal("accepted oversized output bound")
	}
	if _, err := decompressPacket([]byte{17, 0, 0}, -1); err == nil {
		t.Fatal("accepted negative output bound")
	}
	if _, err := compressPacket(make([]byte, 65536)); !errors.Is(err, errLZOTooLarge) {
		t.Fatal("accepted oversized packet")
	}
	// A tiny instruction can request a very long repeated run. Reject while
	// reading its length, before allocating or appending that run.
	bomb := append([]byte{18, 'x', 32}, make([]byte, 300)...)
	bomb = append(bomb, 1, 0, 0, 17, 0, 0)
	if _, err := decompressPacket(bomb, 65535); !errors.Is(err, errLZOTooLarge) {
		t.Fatalf("expansion was not bounded: %v", err)
	}
}

func FuzzDecompressPacket(f *testing.F) {
	f.Add([]byte{17, 0, 0})
	f.Add([]byte{21, 'a', 'b', 'c', 'd', 64, 0, 17, 0, 0})
	f.Fuzz(func(t *testing.T, input []byte) {
		output, err := decompressPacket(input, 65535)
		if err == nil && len(output) > 65535 {
			t.Fatal("decoder exceeded output limit")
		}
	})
}
