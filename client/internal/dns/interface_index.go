package dns

import (
	"fmt"
	"net"
)

func getInterfaceIndex(interfaceName string) (int, error) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return 0, fmt.Errorf("lookup interface %q: %w", interfaceName, err)
	}

	return iface.Index, nil
}
