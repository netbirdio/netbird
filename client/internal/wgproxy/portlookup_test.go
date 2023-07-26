package wgproxy

import (
	"fmt"
	"net"
	"testing"
)

func Test_portLookup_searchFreePort(t *testing.T) {
	pl := portLookup{}
	_, err := pl.searchFreePort()
	if err != nil {
		t.Fatal(err)
	}
}

func Test_portLookup_on_allocated(t *testing.T) {
	pl := portLookup{}

	allocatedPort, err := allocatePort(portRangeStart)
	if err != nil {
		t.Fatal(err)
	}
	defer allocatedPort.Close()

	fp, err := pl.searchFreePort()
	if err != nil {
		t.Fatal(err)
	}

	if fp != (portRangeStart + 1) {
		t.Errorf("invalid free port, expected: %d, got: %d", portRangeStart+1, fp)
	}
}

func allocatePort(port int) (net.PacketConn, error) {
	c, err := net.ListenPacket("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, err
	}
	return c, err
}
