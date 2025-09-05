package bind

import (
	"net"

	wgConn "golang.zx2c4.com/wireguard/conn"
)

type Endpoint = wgConn.StdNetEndpoint

func EndpointToUDPAddr(e Endpoint) *net.UDPAddr {
	return &net.UDPAddr{
		IP:   e.Addr().AsSlice(),
		Port: int(e.Port()),
		Zone: e.Addr().Zone(),
	}
}
