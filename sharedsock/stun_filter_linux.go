package sharedsock

import "golang.org/x/net/bpf"

const magicCookieStun uint32 = 0x2112A442
const magicCookieHealthCheck uint32 = 0x2112A441

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
	raw4, err = rawInstructions(22, 32, dstPort, magicCookieStun, magicCookieHealthCheck)
	if err != nil {
		return nil, nil, err
	}
	raw6, err = rawInstructions(2, 12, dstPort, magicCookieStun, magicCookieHealthCheck)
	if err != nil {
		return nil, nil, err
	}
	return raw4, raw6, nil
}

func rawInstructions(dstPortOff, cookieOff, dstPort, magicCookie, secondMagicCookie uint32) ([]bpf.RawInstruction, error) {
	instructions := []bpf.Instruction{
		// Load the destination port from the UDP header
		bpf.LoadAbsolute{Off: dstPortOff, Size: 2},
		// Check if the destination port matches
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: dstPort, SkipFalse: 3}, // Skip to the end if not equal

		// Load the 4-byte value (magic cookie) from the UDP payload
		bpf.LoadAbsolute{Off: cookieOff, Size: 4},

		// Check if the loaded value is the first magic cookie
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: magicCookie, SkipFalse: 1}, // Proceed to check second cookie if false

		// Return true (match found for the first magic cookie)
		bpf.RetConstant{Val: 0xffffffff},

		// Check if the loaded value is the second magic cookie
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: secondMagicCookie, SkipFalse: 1}, // Skip next if false

		// Return true (match found for the second magic cookie)
		bpf.RetConstant{Val: 0xffffffff},

		// Default return (no match for either cookie)
		bpf.RetConstant{Val: 0},
	}

	return bpf.Assemble(instructions)
}
