package firewall

// PortProtocol is the protocol of the port
type PortProtocol string

const (
	// PortProtocolTCP is the TCP protocol
	PortProtocolTCP PortProtocol = "tcp"

	// PortProtocolUDP is the UDP protocol
	PortProtocolUDP PortProtocol = "udp"
)

// Port of the address for firewall rule
type Port struct {
	// IsRange is true Values contains two values, the first is the start port, the second is the end port
	IsRange bool

	// Values contains one value for single port, multiple values for the list of ports, or two values for the range of ports
	Values []int

	// Proto is the protocol of the port
	Proto PortProtocol
}
