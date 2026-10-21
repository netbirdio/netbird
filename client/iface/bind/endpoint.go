package bind

import (
	"net"

	wgConn "github.com/netbirdio/wireguard-go/conn"
)

type Endpoint = wgConn.StdNetEndpoint

func EndpointToUDPAddr(e Endpoint) *net.UDPAddr {
	return &net.UDPAddr{
		IP:   e.Addr().AsSlice(),
		Port: int(e.Port()),
		Zone: e.Addr().Zone(),
	}
}
