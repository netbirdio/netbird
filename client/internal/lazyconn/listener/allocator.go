package listener

import (
	"fmt"
	"net"
)

const (
	retryLimit = 100
)

var (
	listenIP      = net.ParseIP("127.0.0.254")
	ErrNoFreePort = fmt.Errorf("no free port")
)

// portAllocator lookup for free port and allocate it
type portAllocator struct {
	nextFreePort uint16
}

func newPortAllocator() *portAllocator {
	return &portAllocator{
		nextFreePort: 65535,
	}
}

func (p *portAllocator) newConn() (*net.UDPConn, *net.UDPAddr, error) {
	for i := 0; i < retryLimit; i++ {
		addr := &net.UDPAddr{
			Port: p.nextPort(),
			IP:   listenIP,
		}

		conn, err := net.ListenUDP("udp", addr)
		if err != nil {
			// port could be allocated by another process
			continue
		}

		return conn, addr, nil
	}
	return nil, nil, ErrNoFreePort
}

func (p *portAllocator) nextPort() int {
	port := p.nextFreePort
	p.nextFreePort--
	if p.nextFreePort == 0 {
		p.nextFreePort = 65535
	}
	return int(port)
}
