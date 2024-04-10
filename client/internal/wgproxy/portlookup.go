package wgproxy

import (
	"fmt"
	"net"
)

const (
	portRangeStart = 3128
	portRangeEnd   = 3228
)

type portLookup struct {
}

func (pl portLookup) searchFreePort() (int, error) {
	for i := portRangeStart; i <= portRangeEnd; i++ {
		if pl.tryToBind(i) == nil {
			return i, nil
		}
	}
	return 0, fmt.Errorf("failed to bind free port for eBPF proxy")
}

func (pl portLookup) tryToBind(port int) error {
	l, err := net.ListenPacket("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		return err
	}
	_ = l.Close()
	return nil
}
