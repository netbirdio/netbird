package dns

import "net/netip"

const (
	// MaxGroupNameChar maximum group name size
	MaxGroupNameChar = 40
	// InvalidNameServerType invalid nameserver type
	InvalidNameServerType NameServerType = iota
	// UDPNameServerType udp nameserver type
	UDPNameServerType
)

const (
	// InvalidNameServerTypeString invalid nameserver type as string
	InvalidNameServerTypeString = "invalid"
	// UDPNameServerTypeString udp nameserver type as string
	UDPNameServerTypeString = "udp"
)

// NameServerType nameserver type
type NameServerType int

// String returns nameserver type string
func (n NameServerType) String() string {
	switch n {
	case UDPNameServerType:
		return UDPNameServerTypeString
	default:
		return InvalidNameServerTypeString
	}
}

// ToNameServerType returns a nameserver type
func ToNameServerType(typeString string) NameServerType {
	switch typeString {
	case UDPNameServerTypeString:
		return UDPNameServerType
	default:
		return InvalidNameServerType
	}
}

// NameServerGroup group of nameservers and with group ids
type NameServerGroup struct {
	// ID identifier of group
	ID string
	// Name group name
	Name string
	// Description group description
	Description string
	// NameServers list of nameservers
	NameServers []NameServer
	// Groups list of peer group IDs to distribute the nameservers information
	Groups []string
	// Enabled group status
	Enabled bool
}

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

// Copy copies a nameserver group object
func (g *NameServerGroup) Copy() *NameServerGroup {
	return &NameServerGroup{
		ID:          g.ID,
		Name:        g.Name,
		Description: g.Description,
		NameServers: g.NameServers,
		Groups:      g.Groups,
	}
}

// IsEqual compares one nameserver group with the other
func (g *NameServerGroup) IsEqual(other *NameServerGroup) bool {
	return other.ID == g.ID &&
		other.Name == g.Name &&
		other.Description == g.Description &&
		compareNameServerList(g.NameServers, other.NameServers) &&
		compareGroupsList(g.Groups, other.Groups)
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
