//go:build linux && !android

package wgproxy

import (
	"context"
	"testing"
)

func TestWGEBPFProxy_connStore(t *testing.T) {
	wgProxy := NewWGEBPFProxy(context.Background(), 1)

	p, _ := wgProxy.storeTurnConn(nil)
	if p != 1 {
		t.Errorf("invalid initial port: %d", wgProxy.lastUsedPort)
	}

	numOfConns := 10
	for i := 0; i < numOfConns; i++ {
		p, _ = wgProxy.storeTurnConn(nil)
	}
	if p != uint16(numOfConns)+1 {
		t.Errorf("invalid last used port: %d, expected: %d", p, numOfConns+1)
	}
	if len(wgProxy.turnConnStore) != numOfConns+1 {
		t.Errorf("invalid store size: %d, expected: %d", len(wgProxy.turnConnStore), numOfConns+1)
	}
}

func TestWGEBPFProxy_portCalculation_overflow(t *testing.T) {
	wgProxy := NewWGEBPFProxy(context.Background(), 1)

	_, _ = wgProxy.storeTurnConn(nil)
	wgProxy.lastUsedPort = 65535
	p, _ := wgProxy.storeTurnConn(nil)

	if len(wgProxy.turnConnStore) != 2 {
		t.Errorf("invalid store size: %d, expected: %d", len(wgProxy.turnConnStore), 2)
	}

	if p != 2 {
		t.Errorf("invalid last used port: %d, expected: %d", p, 2)
	}
}

func TestWGEBPFProxy_portCalculation_maxConn(t *testing.T) {
	wgProxy := NewWGEBPFProxy(context.Background(), 1)

	for i := 0; i < 65535; i++ {
		_, _ = wgProxy.storeTurnConn(nil)
	}

	_, err := wgProxy.storeTurnConn(nil)
	if err == nil {
		t.Errorf("invalid turn conn store calculation")
	}
}
