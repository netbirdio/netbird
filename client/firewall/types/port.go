package types

import (
	"strconv"
)

// Port of the address for firewall rule
type Port struct {
	// IsRange is true Values contains two values, the first is the start port, the second is the end port
	IsRange bool

	// Values contains one value for single port, multiple values for the list of ports, or two values for the range of ports
	Values []int
}

// String interface implementation
func (p *Port) String() string {
	var ports string
	for _, port := range p.Values {
		if ports != "" {
			ports += ","
		}
		ports += strconv.Itoa(port)
	}
	return ports
}
