//go:build !linux

package quic

import "net"

const canShareUDPPort = false

func listenUDP(address string, _ bool) (*net.UDPConn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, err
	}
	return net.ListenUDP("udp", udpAddr)
}
