package firewall

// Protocol is the protocol of the port
type Protocol string

const (
	// ProtocolTCP is the TCP protocol
	ProtocolTCP Protocol = "tcp"

	// ProtocolUDP is the UDP protocol
	ProtocolUDP Protocol = "udp"

	// ProtocolICMP is the ICMP protocol
	ProtocolICMP Protocol = "icmp"
)

// Port of the address for firewall rule
type Port struct {
	// IsRange is true Values contains two values, the first is the start port, the second is the end port
	IsRange bool

	// Values contains one value for single port, multiple values for the list of ports, or two values for the range of ports
	Values []int
}
