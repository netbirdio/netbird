package types

// Protocol is the protocol of the port
type Protocol string

const (
	// ProtocolTCP is the TCP protocol
	ProtocolTCP Protocol = "tcp"

	// ProtocolUDP is the UDP protocol
	ProtocolUDP Protocol = "udp"

	// ProtocolICMP is the ICMP protocol
	ProtocolICMP Protocol = "icmp"

	// ProtocolALL cover all supported protocols
	ProtocolALL Protocol = "all"

	// ProtocolUnknown unknown protocol
	ProtocolUnknown Protocol = "unknown"
)
