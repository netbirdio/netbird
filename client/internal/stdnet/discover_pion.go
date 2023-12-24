package stdnet

import (
	"net"

	"github.com/pion/transport/v3"
)

type pionDiscover struct {
}

func (d pionDiscover) iFaces() ([]*transport.Interface, error) {
	ifs := []*transport.Interface{}

	oifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, oif := range oifs {
		ifc := transport.NewInterface(oif)

		addrs, err := oif.Addrs()
		if err != nil {
			return nil, err
		}

		for _, addr := range addrs {
			ifc.AddAddress(addr)
		}

		ifs = append(ifs, ifc)
	}

	return ifs, nil
}
