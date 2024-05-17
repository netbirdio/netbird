package tcp

import "net"

func Dial(address string) (net.Conn, error) {
	return net.Dial("tcp", address)
}
