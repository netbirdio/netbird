package sharedsock

import "golang.org/x/net/bpf"

const magicCookie uint32 = 0x2112A442

// IncomingSTUNFilter implements BPFFilter and filters out anything but incoming STUN packets to a specified destination port.
// Other packets (non STUN) will be forwarded to the process that own the port (e.g., WireGuard).
type IncomingSTUNFilter struct {
}

// NewIncomingSTUNFilter creates an instance of a IncomingSTUNFilter
func NewIncomingSTUNFilter() BPFFilter {
	return &IncomingSTUNFilter{}
}

// GetInstructions returns raw BPF instructions for ipv4 and ipv6 that filter out anything but STUN packets
func (filter *IncomingSTUNFilter) GetInstructions(dstPort uint32) (raw4 []bpf.RawInstruction, raw6 []bpf.RawInstruction, err error) {
	raw4, err = rawInstructions(22, 32, dstPort)
	if err != nil {
		return nil, nil, err
	}
	raw6, err = rawInstructions(2, 12, dstPort)
	if err != nil {
		return nil, nil, err
	}
	return raw4, raw6, nil
}

func rawInstructions(dstPortOff, cookieOff, dstPort uint32) ([]bpf.RawInstruction, error) {
	// UDP raw socket for ipv4 receives the rcvdPacket with IP headers
	// UDP raw socket for ipv6 receives the rcvdPacket with UDP headers
	instructions := []bpf.Instruction{
		// Load the destination port from the UDP header (offset 22 for ipv4 and 2 for ipv6)
		bpf.LoadAbsolute{Off: dstPortOff, Size: 2},
		// Check if the destination port is equal to the specified `dstPort`. If not, skip the next 3 instructions.
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: dstPort, SkipTrue: 3},
		// Load the 4-byte value (magic cookie) from the UDP payload (offset 32 for ipv4 and 12 for ipv6)
		bpf.LoadAbsolute{Off: cookieOff, Size: 4},
		// Check if the loaded value is equal to the `magicCookie`. If not, skip the next instruction.
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: magicCookie, SkipTrue: 1},
		// If both the dstPort and the magic cookie match, return a positive value (0xffffffff)
		bpf.RetConstant{Val: 0xffffffff},
		// If either the dstPort or the magic cookie doesn't match, return 0
		bpf.RetConstant{Val: 0},
	}

	return bpf.Assemble(instructions)
}
