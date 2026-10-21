package bind

import (
	"net"

	"github.com/netbirdio/netbird/client/iface/wgbackend"
)

type Endpoint = wgbackend.StdNetEndpoint

func EndpointToUDPAddr(e Endpoint) *net.UDPAddr {
	return &net.UDPAddr{
		IP:   e.Addr().AsSlice(),
		Port: int(e.Port()),
		Zone: e.Addr().Zone(),
	}
}
