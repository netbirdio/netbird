//go:build linux && !android

package ebpf

import (
	"testing"
)

func TestWGEBPFProxy_connStore(t *testing.T) {
	wgProxy := NewWGEBPFProxy(1, 1280)

	p, _ := wgProxy.storeRelayedConn(nil)
	if p != 1 {
		t.Errorf("invalid initial port: %d", wgProxy.lastUsedPort)
	}

	numOfConns := 10
	for i := 0; i < numOfConns; i++ {
		p, _ = wgProxy.storeRelayedConn(nil)
	}
	if p != uint16(numOfConns)+1 {
		t.Errorf("invalid last used port: %d, expected: %d", p, numOfConns+1)
	}
	if len(wgProxy.relayedConnStore) != numOfConns+1 {
		t.Errorf("invalid store size: %d, expected: %d", len(wgProxy.relayedConnStore), numOfConns+1)
	}
}

func TestWGEBPFProxy_portCalculation_overflow(t *testing.T) {
	wgProxy := NewWGEBPFProxy(1, 1280)

	_, _ = wgProxy.storeRelayedConn(nil)
	wgProxy.lastUsedPort = 65535
	p, _ := wgProxy.storeRelayedConn(nil)

	if len(wgProxy.relayedConnStore) != 2 {
		t.Errorf("invalid store size: %d, expected: %d", len(wgProxy.relayedConnStore), 2)
	}

	if p != 2 {
		t.Errorf("invalid last used port: %d, expected: %d", p, 2)
	}
}

func TestWGEBPFProxy_portCalculation_maxConn(t *testing.T) {
	wgProxy := NewWGEBPFProxy(1, 1280)

	for i := 0; i < 65535; i++ {
		_, _ = wgProxy.storeRelayedConn(nil)
	}

	_, err := wgProxy.storeRelayedConn(nil)
	if err == nil {
		t.Errorf("invalid relayed conn store calculation")
	}
}
