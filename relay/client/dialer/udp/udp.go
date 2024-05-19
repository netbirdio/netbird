package udp

import (
	"net"
)

func Dial(address string) (net.Conn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, err
	}

	return net.DialUDP("udp", nil, udpAddr)
}
