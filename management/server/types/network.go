package types

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/c-robinson/iplib"
	"github.com/rs/xid"
	"golang.org/x/exp/maps"

	nbdns "github.com/netbirdio/netbird/dns"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/util"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/shared/management/status"
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
	AuthorizedUsers     map[string]map[string]struct{}
	EnableSSH           bool
}

func (nm *NetworkMap) Merge(other *NetworkMap) {
	nm.Peers = mergeUniquePeersByID(nm.Peers, other.Peers)
	nm.Routes = util.MergeUnique(nm.Routes, other.Routes)
	nm.OfflinePeers = mergeUniquePeersByID(nm.OfflinePeers, other.OfflinePeers)
	nm.FirewallRules = util.MergeUnique(nm.FirewallRules, other.FirewallRules)
	nm.RoutesFirewallRules = util.MergeUnique(nm.RoutesFirewallRules, other.RoutesFirewallRules)
	nm.ForwardingRules = util.MergeUnique(nm.ForwardingRules, other.ForwardingRules)
}

func (nm *NetworkMap) UncompactRoutes() {
	peers := make(map[string]*nbpeer.Peer, len(nm.Peers)+len(nm.OfflinePeers))
	for _, p := range nm.Peers {
		peers[p.ID] = p
	}
	uncompactedRoutes := make([]*route.Route, 0)
	for _, compactRoute := range nm.Routes {
		if len(compactRoute.ApplicablePeerIDs) == 0 {
			uncompactedRoutes = append(uncompactedRoutes, compactRoute.Copy())
			continue
		}

		for _, peerID := range compactRoute.ApplicablePeerIDs {
			expandedRoute := compactRoute.Copy()
			expandedRoute.ID = route.ID(string(compactRoute.ID) + ":" + peerID)
			peer := peers[peerID]
			if peer == nil {
				continue
			}
			expandedRoute.Peer = peer.Key
			expandedRoute.PeerID = peerID
			uncompactedRoutes = append(uncompactedRoutes, expandedRoute)
		}
	}

	nm.Routes = uncompactedRoutes
}

func (nm *NetworkMap) UncompactFirewallRules() {
	uncompactedRules := make([]*FirewallRule, 0, len(nm.FirewallRules)*2)

	for _, compactRule := range nm.FirewallRules {
		if len(compactRule.PeerIPs) == 0 {
			uncompactedRules = append(uncompactedRules, compactRule)
			continue
		}

		for _, peerIP := range compactRule.PeerIPs {
			if len(compactRule.Ports) > 0 {
				for _, port := range compactRule.Ports {
					expandedRule := &FirewallRule{
						PolicyID:  compactRule.PolicyID,
						PeerIP:    peerIP,
						Direction: compactRule.Direction,
						Action:    compactRule.Action,
						Protocol:  compactRule.Protocol,
						Port:      port,
					}
					uncompactedRules = append(uncompactedRules, expandedRule)
				}
			} else if len(compactRule.PortRanges) > 0 {
				for _, portRange := range compactRule.PortRanges {
					expandedRule := &FirewallRule{
						PolicyID:  compactRule.PolicyID,
						PeerIP:    peerIP,
						Direction: compactRule.Direction,
						Action:    compactRule.Action,
						Protocol:  compactRule.Protocol,
						PortRange: portRange,
					}
					uncompactedRules = append(uncompactedRules, expandedRule)
				}
			} else {
				expandedRule := &FirewallRule{
					PolicyID:  compactRule.PolicyID,
					PeerIP:    peerIP,
					Direction: compactRule.Direction,
					Action:    compactRule.Action,
					Protocol:  compactRule.Protocol,
					Port:      compactRule.Port,
					PortRange: compactRule.PortRange,
				}
				uncompactedRules = append(uncompactedRules, expandedRule)
			}
		}
	}

	nm.FirewallRules = uncompactedRules
}

func (nm *NetworkMap) ValidateApplicablePeerIDs(compactNm *NetworkMap, expectedPermsMap map[string]map[string]bool) error {
	if compactNm == nil {
		return fmt.Errorf("compact network map is nil")
	}

	peerIDSet := make(map[string]struct{})
	for _, peer := range nm.Peers {
		peerIDSet[peer.ID] = struct{}{}
	}

	for _, route := range compactNm.Routes {
		if len(route.ApplicablePeerIDs) == 0 {
			continue
		}

		for _, peerID := range route.ApplicablePeerIDs {
			if _, exists := peerIDSet[peerID]; !exists {
				return fmt.Errorf("route %s has applicable peer ID %s that doesn't exist in peer list", route.ID, peerID)
			}
		}

		if expectedPermsMap != nil {
			expected, hasExpected := expectedPermsMap[string(route.ID)]
			if hasExpected {
				expectedPeerIDs := make(map[string]struct{})
				for peerID, shouldAccess := range expected {
					if shouldAccess {
						expectedPeerIDs[peerID] = struct{}{}
					}
				}

				if len(route.ApplicablePeerIDs) != len(expectedPeerIDs) {
					return fmt.Errorf("route %s: expected %d applicable peers, got %d",
						route.ID, len(expectedPeerIDs), len(route.ApplicablePeerIDs))
				}

				for _, peerID := range route.ApplicablePeerIDs {
					if _, expected := expectedPeerIDs[peerID]; !expected {
						return fmt.Errorf("route %s: peer %s should not have access but is in ApplicablePeerIDs",
							route.ID, peerID)
					}
				}
			}
		}
	}

	return nil
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
	baseIP := ipToUint32(ipNet.IP.Mask(ipNet.Mask))

	ones, bits := ipNet.Mask.Size()
	hostBits := bits - ones
	totalIPs := uint32(1 << hostBits)

	taken := make(map[uint32]struct{}, len(takenIps)+1)
	taken[baseIP] = struct{}{}            // reserve network IP
	taken[baseIP+totalIPs-1] = struct{}{} // reserve broadcast IP

	for _, ip := range takenIps {
		taken[ipToUint32(ip)] = struct{}{}
	}

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	maxAttempts := (int(totalIPs) - len(taken)) / 100

	for i := 0; i < maxAttempts; i++ {
		offset := uint32(rng.Intn(int(totalIPs-2))) + 1
		candidate := baseIP + offset
		if _, exists := taken[candidate]; !exists {
			return uint32ToIP(candidate), nil
		}
	}

	for offset := uint32(1); offset < totalIPs-1; offset++ {
		candidate := baseIP + offset
		if _, exists := taken[candidate]; !exists {
			return uint32ToIP(candidate), nil
		}
	}

	return nil, status.Errorf(status.PreconditionFailed, "network %s is out of IPs", ipNet.String())
}

func AllocateRandomPeerIP(ipNet net.IPNet) (net.IP, error) {
	baseIP := ipToUint32(ipNet.IP.Mask(ipNet.Mask))

	ones, bits := ipNet.Mask.Size()
	hostBits := bits - ones

	totalIPs := uint32(1 << hostBits)

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	offset := uint32(rng.Intn(int(totalIPs-2))) + 1

	candidate := baseIP + offset
	return uint32ToIP(candidate), nil
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if len(ip) < 4 {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}

func uint32ToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip
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
