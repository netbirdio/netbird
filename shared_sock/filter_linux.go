//go:build linux && !android

package shared_sock

import (
	"golang.org/x/net/bpf"
)

const magicCookie uint32 = 0x2112A442

func getBPFInstructions(port uint32) ([]bpf.RawInstruction, []bpf.RawInstruction, error) {
	raw4, err := rawInstructions(22, 32, port)
	if err != nil {
		return nil, nil, err
	}
	raw6, err := rawInstructions(2, 12, port)
	if err != nil {
		return nil, nil, err
	}
	return raw4, raw6, nil
}

func rawInstructions(portOff, cookieOff, port uint32) ([]bpf.RawInstruction, error) {
	// UDP raw socket for ipv4 receives the rcvdPacket with IP headers
	// UDP raw socket for ipv6 receives the rcvdPacket with UDP headers
	instructions := []bpf.Instruction{
		// Load the source port from the UDP header (offset 22 for ipv4 and 2 for ipv6)
		bpf.LoadAbsolute{Off: portOff, Size: 2},
		// Check if the source port is equal to the specified `port`. If not, skip the next 3 instructions.
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: port, SkipTrue: 3},
		// Load the 4-byte value (magic cookie) from the UDP payload (offset 32 for ipv4 and 12 for ipv6)
		bpf.LoadAbsolute{Off: cookieOff, Size: 4},
		// Check if the loaded value is equal to the `magicCookie`. If not, skip the next instruction.
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: magicCookie, SkipTrue: 1},
		// If both the port and the magic cookie match, return a positive value (0xffffffff)
		bpf.RetConstant{Val: 0xffffffff},
		// If either the port or the magic cookie doesn't match, return 0
		bpf.RetConstant{Val: 0},
	}

	return bpf.Assemble(instructions)
}
