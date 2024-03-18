package types

import "net/netip"

// NameServerType nameserver type
type NameServerType int

// NameServer represents a DNS nameserver
type NameServer struct {
	// IP address of nameserver
	IP netip.Addr
	// NSType nameserver type
	NSType NameServerType
	// Port nameserver listening port
	Port int
}

// Copy copies a nameserver object
func (n *NameServer) Copy() *NameServer {
	return &NameServer{
		IP:     n.IP,
		NSType: n.NSType,
		Port:   n.Port,
	}
}

// IsEqual compares one nameserver with the other
func (n *NameServer) IsEqual(other *NameServer) bool {
	return other.IP == n.IP &&
		other.NSType == n.NSType &&
		other.Port == n.Port
}

func compareNameServerList(list, other []NameServer) bool {
	if len(list) != len(other) {
		return false
	}

	for _, ns := range list {
		if !containsNameServer(ns, other) {
			return false
		}
	}

	return true
}

func containsNameServer(element NameServer, list []NameServer) bool {
	for _, ns := range list {
		if ns.IsEqual(&element) {
			return true
		}
	}
	return false
}

func compareGroupsList(list, other []string) bool {
	if len(list) != len(other) {
		return false
	}
	for _, id := range list {
		match := false
		for _, otherID := range other {
			if id == otherID {
				match = true
				break
			}
		}
		if !match {
			return false
		}
	}

	return true
}
