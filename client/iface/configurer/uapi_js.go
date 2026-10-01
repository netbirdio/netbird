package configurer

import (
	"net"
)

type noopListener struct{}

func (n *noopListener) Accept() (net.Conn, error) {
	return nil, net.ErrClosed
}

func (n *noopListener) Close() error {
	return nil
}

func (n *noopListener) Addr() net.Addr {
	return nil
}

func openUAPI(deviceName string) (net.Listener, error) {
	return &noopListener{}, nil
}
