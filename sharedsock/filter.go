package sharedsock

import "golang.org/x/net/bpf"

const magicCookie uint32 = 0x2112A442

// BPFFilter is a generic filter that provides ipv4 and ipv6 BPF instructions
type BPFFilter interface {
	// GetInstructions returns raw BPF instructions for ipv4 and ipv6
	GetInstructions(port uint32) (ipv4 []bpf.RawInstruction, ipv6 []bpf.RawInstruction, err error)
}
