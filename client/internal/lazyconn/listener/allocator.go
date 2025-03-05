package listener

import (
	"fmt"
	"net"

	log "github.com/sirupsen/logrus"
)

const (
	retryLimit = 5000
)

var (
	listenIP      = net.ParseIP("127.0.0.1")
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
			log.Errorf("failed to listen on port %d: %v", addr.Port, err)
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
	if p.nextFreePort == 1024 {
		p.nextFreePort = 65535
	}
	return int(port)
}
