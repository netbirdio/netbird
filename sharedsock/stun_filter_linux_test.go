//go:build linux && !android

package sharedsock

import (
	"encoding/binary"
	"testing"

	"golang.org/x/net/bpf"
)

const testPort = 51820

// ipv4STUNPacket builds an IPv4 datagram carrying a STUN message, with the given
// number of 4-byte IP option words. optionWords of 0 gives the usual 20-byte header.
func ipv4STUNPacket(optionWords int, dstPort uint16, cookie uint32) []byte {
	ihl := 5 + optionWords
	hdr := make([]byte, ihl*4)
	hdr[0] = 0x40 | byte(ihl)
	hdr[9] = 17 // UDP

	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], 12345)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)

	payload := make([]byte, 20)
	binary.BigEndian.PutUint16(payload[0:2], 0x0001) // binding request
	binary.BigEndian.PutUint32(payload[4:8], cookie)

	return append(append(hdr, udp...), payload...)
}

// ipv6STUNPacket builds what an ipv6 raw socket delivers: the UDP header onward.
func ipv6STUNPacket(dstPort uint16, cookie uint32) []byte {
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], 12345)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)

	payload := make([]byte, 20)
	binary.BigEndian.PutUint16(payload[0:2], 0x0001)
	binary.BigEndian.PutUint32(payload[4:8], cookie)

	return append(udp, payload...)
}

func runFilter(t *testing.T, raw []bpf.RawInstruction, packet []byte) int {
	t.Helper()

	insts, ok := bpf.Disassemble(raw)
	if !ok {
		t.Fatal("disassemble produced unknown instructions")
	}
	vm, err := bpf.NewVM(insts)
	if err != nil {
		t.Fatalf("new vm: %v", err)
	}
	n, err := vm.Run(packet)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	return n
}

func TestIncomingSTUNFilterIPv4(t *testing.T) {
	raw4, _, err := NewIncomingSTUNFilter().GetInstructions(testPort)
	if err != nil {
		t.Fatalf("get instructions: %v", err)
	}

	tests := []struct {
		name        string
		optionWords int
		dstPort     uint16
		cookie      uint32
		wantMatch   bool
	}{
		{"no options", 0, testPort, magicCookie, true},
		{"one option word", 1, testPort, magicCookie, true},
		{"three option words", 3, testPort, magicCookie, true},
		{"wrong port", 0, testPort + 1, magicCookie, false},
		{"wrong port with options", 2, testPort + 1, magicCookie, false},
		{"not stun", 0, testPort, 0xdeadbeef, false},
		{"not stun with options", 2, testPort, 0xdeadbeef, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			packet := ipv4STUNPacket(tc.optionWords, tc.dstPort, tc.cookie)
			got := runFilter(t, raw4, packet) > 0
			if got != tc.wantMatch {
				t.Errorf("match = %v, want %v", got, tc.wantMatch)
			}
		})
	}
}

func TestIncomingSTUNFilterIPv6(t *testing.T) {
	_, raw6, err := NewIncomingSTUNFilter().GetInstructions(testPort)
	if err != nil {
		t.Fatalf("get instructions: %v", err)
	}

	if runFilter(t, raw6, ipv6STUNPacket(testPort, magicCookie)) == 0 {
		t.Error("stun packet did not match")
	}
	if runFilter(t, raw6, ipv6STUNPacket(testPort+1, magicCookie)) > 0 {
		t.Error("packet for another port matched")
	}
	if runFilter(t, raw6, ipv6STUNPacket(testPort, 0xdeadbeef)) > 0 {
		t.Error("non-stun packet matched")
	}
}
