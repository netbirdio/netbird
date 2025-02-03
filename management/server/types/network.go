package types

import (
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/c-robinson/iplib"
	"github.com/rs/xid"
	"golang.org/x/exp/maps"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/proto"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/status"
	"github.com/netbirdio/netbird/management/server/util"
	"github.com/netbirdio/netbird/route"
)

const (
	// SubnetSize is a size of the subnet of the global network, e.g.  100.77.0.0/16
	SubnetSize = 16
	// NetSize is a global network size 100.64.0.0/10
	NetSize = 10

	// AllowedIPsFormat generates Wireguard AllowedIPs format (e.g. 100.64.30.1/32)
	AllowedIPsFormat = "%s/32"
)

type NetworkMap struct {
	Peers               []*nbpeer.Peer
	Network             *Network
	Routes              []*route.Route
	DNSConfig           nbdns.Config
	OfflinePeers        []*nbpeer.Peer
	FirewallRules       []*FirewallRule
	RoutesFirewallRules []*RouteFirewallRule
	ForwardingRules     []*ForwardingRule
}

func (nm *NetworkMap) Merge(other *NetworkMap) {
	nm.Peers = mergeUniquePeersByID(nm.Peers, other.Peers)
	nm.Routes = util.MergeUnique(nm.Routes, other.Routes)
	nm.OfflinePeers = mergeUniquePeersByID(nm.OfflinePeers, other.OfflinePeers)
	nm.FirewallRules = util.MergeUnique(nm.FirewallRules, other.FirewallRules)
	nm.RoutesFirewallRules = util.MergeUnique(nm.RoutesFirewallRules, other.RoutesFirewallRules)
	nm.ForwardingRules = util.MergeUnique(nm.ForwardingRules, other.ForwardingRules)
}

func mergeUniquePeersByID(peers1, peers2 []*nbpeer.Peer) []*nbpeer.Peer {
	result := make(map[string]*nbpeer.Peer)
	for _, peer := range peers1 {
		result[peer.ID] = peer
	}
	for _, peer := range peers2 {
		if _, ok := result[peer.ID]; !ok {
			result[peer.ID] = peer
		}
	}

	return maps.Values(result)
}

type ForwardingRule struct {
	RuleProtocol      string
	DestinationPorts  RulePortRange
	TranslatedAddress net.IP
	TranslatedPorts   RulePortRange
}

func (f *ForwardingRule) ToProto() *proto.ForwardingRule {
	var protocol proto.RuleProtocol
	switch f.RuleProtocol {
	case "icmp":
		protocol = proto.RuleProtocol_ICMP
	case "tcp":
		protocol = proto.RuleProtocol_TCP
	case "udp":
		protocol = proto.RuleProtocol_UDP
	case "all":
		protocol = proto.RuleProtocol_ALL
	default:
		protocol = proto.RuleProtocol_UNKNOWN
	}
	return &proto.ForwardingRule{
		Protocol:          protocol,
		DestinationPort:   f.DestinationPorts.ToProto(),
		TranslatedAddress: ipToBytes(f.TranslatedAddress),
		TranslatedPort:    f.TranslatedPorts.ToProto(),
	}
}

func (f *ForwardingRule) Equal(other *ForwardingRule) bool {
	return f.RuleProtocol == other.RuleProtocol &&
		f.DestinationPorts.Equal(&other.DestinationPorts) &&
		f.TranslatedAddress.Equal(other.TranslatedAddress) &&
		f.TranslatedPorts.Equal(&other.TranslatedPorts)
}

func ipToBytes(ip net.IP) []byte {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4
	}
	return ip.To16()
}

type Network struct {
	Identifier string    `json:"id"`
	Net        net.IPNet `gorm:"serializer:json"`
	Dns        string
	// Serial is an ID that increments by 1 when any change to the network happened (e.g. new peer has been added).
	// Used to synchronize state to the client apps.
	Serial uint64

	Mu sync.Mutex `json:"-" gorm:"-"`
}

// NewNetwork creates a new Network initializing it with a Serial=0
// It takes a random /16 subnet from 100.64.0.0/10 (64 different subnets)
func NewNetwork() *Network {

	n := iplib.NewNet4(net.ParseIP("100.64.0.0"), NetSize)
	sub, _ := n.Subnet(SubnetSize)

	s := rand.NewSource(time.Now().Unix())
	r := rand.New(s)
	intn := r.Intn(len(sub))

	return &Network{
		Identifier: xid.New().String(),
		Net:        sub[intn].IPNet,
		Dns:        "",
		Serial:     0}
}

// IncSerial increments Serial by 1 reflecting that the network state has been changed
func (n *Network) IncSerial() {
	n.Mu.Lock()
	defer n.Mu.Unlock()
	n.Serial++
}

// CurrentSerial returns the Network.Serial of the network (latest state id)
func (n *Network) CurrentSerial() uint64 {
	n.Mu.Lock()
	defer n.Mu.Unlock()
	return n.Serial
}

func (n *Network) Copy() *Network {
	return &Network{
		Identifier: n.Identifier,
		Net:        n.Net,
		Dns:        n.Dns,
		Serial:     n.Serial,
	}
}

// AllocatePeerIP pics an available IP from an net.IPNet.
// This method considers already taken IPs and reuses IPs if there are gaps in takenIps
// E.g. if ipNet=100.30.0.0/16 and takenIps=[100.30.0.1, 100.30.0.4] then the result would be 100.30.0.2 or 100.30.0.3
func AllocatePeerIP(ipNet net.IPNet, takenIps []net.IP) (net.IP, error) {
	takenIPMap := make(map[string]struct{})
	takenIPMap[ipNet.IP.String()] = struct{}{}
	for _, ip := range takenIps {
		takenIPMap[ip.String()] = struct{}{}
	}

	ips, _ := generateIPs(&ipNet, takenIPMap)

	if len(ips) == 0 {
		return nil, status.Errorf(status.PreconditionFailed, "failed allocating new IP for the ipNet %s - network is out of IPs", ipNet.String())
	}

	// pick a random IP
	s := rand.NewSource(time.Now().Unix())
	r := rand.New(s)
	intn := r.Intn(len(ips))

	return ips[intn], nil
}

// generateIPs generates a list of all possible IPs of the given network excluding IPs specified in the exclusion list
func generateIPs(ipNet *net.IPNet, exclusions map[string]struct{}) ([]net.IP, int) {

	var ips []net.IP
	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incIP(ip) {
		if _, ok := exclusions[ip.String()]; !ok && ip[3] != 0 {
			ips = append(ips, copyIP(ip))
		}
	}

	// remove network address, broadcast and Fake DNS resolver address
	lenIPs := len(ips)
	switch {
	case lenIPs < 2:
		return ips, lenIPs
	case lenIPs < 3:
		return ips[1 : len(ips)-1], lenIPs - 2
	default:
		return ips[1 : len(ips)-2], lenIPs - 3
	}
}

func copyIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
