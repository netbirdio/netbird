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
	raw4, err = rawInstructions4(dstPort)
	if err != nil {
		return nil, nil, err
	}
	raw6, err = rawInstructions6(dstPort)
	if err != nil {
		return nil, nil, err
	}
	return raw4, raw6, nil
}

// rawInstructions4 filters an ipv4 raw socket, which delivers the IP header along
// with the packet. The IP header length varies, so the UDP header is located
// through the IHL field rather than at a fixed offset. Reading the destination
// port at a fixed 22 would miss every datagram carrying IP options.
func rawInstructions4(dstPort uint32) ([]bpf.RawInstruction, error) {
	instructions := []bpf.Instruction{
		// Put the IP header length into X, so the UDP header starts at X.
		bpf.LoadMemShift{Off: 0},
		// Load the destination port from the UDP header.
		bpf.LoadIndirect{Off: 2, Size: 2},
		// Check if the destination port is equal to the specified `dstPort`. If not, skip the next 3 instructions.
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: dstPort, SkipTrue: 3},
		// Load the 4-byte value (magic cookie) from the UDP payload.
		bpf.LoadIndirect{Off: 12, Size: 4},
		// Check if the loaded value is equal to the `magicCookie`. If not, skip the next instruction.
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: magicCookie, SkipTrue: 1},
		// If both the dstPort and the magic cookie match, return a positive value (0xffffffff)
		bpf.RetConstant{Val: 0xffffffff},
		// If either the dstPort or the magic cookie doesn't match, return 0
		bpf.RetConstant{Val: 0},
	}

	return bpf.Assemble(instructions)
}

// rawInstructions6 filters an ipv6 raw socket. The kernel strips the IPv6 header
// and any extension headers, so the packet starts at the UDP header.
func rawInstructions6(dstPort uint32) ([]bpf.RawInstruction, error) {
	instructions := []bpf.Instruction{
		// Load the destination port from the UDP header.
		bpf.LoadAbsolute{Off: 2, Size: 2},
		// Check if the destination port is equal to the specified `dstPort`. If not, skip the next 3 instructions.
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: dstPort, SkipTrue: 3},
		// Load the 4-byte value (magic cookie) from the UDP payload.
		bpf.LoadAbsolute{Off: 12, Size: 4},
		// Check if the loaded value is equal to the `magicCookie`. If not, skip the next instruction.
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: magicCookie, SkipTrue: 1},
		// If both the dstPort and the magic cookie match, return a positive value (0xffffffff)
		bpf.RetConstant{Val: 0xffffffff},
		// If either the dstPort or the magic cookie doesn't match, return 0
		bpf.RetConstant{Val: 0},
	}

	return bpf.Assemble(instructions)
}
