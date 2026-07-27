package nmdata

import "net"

// Network is the slim twin of types.Network.
type Network struct {
	Identifier string
	Net        net.IPNet
	NetV6      net.IPNet
	Dns        string
	Serial     uint64
}

func (n *Network) CurrentSerial() uint64 {
	return n.Serial
}
