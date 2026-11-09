package nmdata

import "net"

// Network is the slim twin of types.Network.
type Network struct {
	Identifier string
	Net        net.IPNet
	NetV6      net.IPNet
	Dns        string
	Serial     int64
}

func (n *Network) CurrentSerial() uint64 {
	return uint64(n.Serial)
}
