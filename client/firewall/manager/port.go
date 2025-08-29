package manager

import (
	"fmt"
	"strconv"
)

// Port of the address for firewall rule
// todo Move Protocol and Port and RouterPair to the Firwall package or a separate package
type Port struct {
	// IsRange is true Values contains two values, the first is the start port, the second is the end port
	IsRange bool

	// Values contains one value for single port, multiple values for the list of ports, or two values for the range of ports
	Values []uint16
}

func NewPort(ports ...int) (*Port, error) {
	if len(ports) == 0 {
		return nil, fmt.Errorf("no port provided")
	}

	ports16 := make([]uint16, len(ports))
	for i, port := range ports {
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid port number: %d (must be between 1-65535)", port)
		}
		ports16[i] = uint16(port)
	}

	return &Port{
		IsRange: len(ports) > 1,
		Values:  ports16,
	}, nil
}

// String interface implementation
func (p *Port) String() string {
	var ports string
	for _, port := range p.Values {
		if ports != "" {
			ports += ","
		}
		ports += strconv.Itoa(int(port))
	}
	if p.IsRange {
		ports = "range:" + ports
	}

	return ports
}
