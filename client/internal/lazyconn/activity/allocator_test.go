package activity

import (
	"testing"
)

func Test_portAllocator_newConn(t *testing.T) {
	pa := newPortAllocator()
	for i := 65535; i > 65535-10; i-- {
		conn, addr, err := pa.newConn()
		if err != nil {
			t.Fatalf("newConn() error = %v, want nil", err)
		}
		if addr.Port != i {
			t.Errorf("newConn() addr.Port = %v, want %d", addr.Port, i)
		}
		_ = conn.Close()
	}
}

func Test_portAllocator_port_bottom(t *testing.T) {
	pa := newPortAllocator()
	pa.nextFreePort = 1025

	port := pa.nextPort()
	if port != 1025 {
		t.Errorf("nextPort() = %v, want %d", port, 1)
	}

	port = pa.nextPort()
	if port != 65535 {
		t.Errorf("nextPort() = %v, want %d", port, 65535)
	}
}
