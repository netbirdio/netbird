package manager

// Protocol is the protocol of the port
// todo Move Protocol and Port and RouterPair to the Firwall package or a separate package
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
)
