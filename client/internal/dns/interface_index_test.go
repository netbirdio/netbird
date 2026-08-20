package dns

import (
	"net"
	"testing"
)

func TestGetInterfaceIndexExisting(t *testing.T) {
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("list network interfaces: %v", err)
	}
	if len(interfaces) == 0 {
		t.Fatal("expected at least one network interface")
	}

	iface := interfaces[0]
	index, err := getInterfaceIndex(iface.Name)
	if err != nil {
		t.Fatalf("look up existing interface %q: %v", iface.Name, err)
	}
	if index != iface.Index {
		t.Fatalf("expected interface index %d, got %d", iface.Index, index)
	}
}

func TestGetInterfaceIndexMissing(t *testing.T) {
	index, err := getInterfaceIndex("netbird-interface-that-does-not-exist")
	if index != 0 {
		t.Fatalf("expected missing interface index to be 0, got %d", index)
	}
	if err == nil {
		t.Fatal("expected missing interface lookup to return an error")
	}
}
