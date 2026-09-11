package types

import (
	"net"

	"golang.org/x/exp/maps"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	"github.com/netbirdio/netbird/shared/management/proto"
)

const (
	// AllowedIPsFormat generates Wireguard AllowedIPs format (e.g. 100.64.30.1/32)
	AllowedIPsFormat = "%s/32"
	// AllowedIPsV6Format generates AllowedIPs format for v6 (e.g. fd12:3456:7890::1/128)
	AllowedIPsV6Format = "%s/128"
)

type NetworkMap struct {
	Peers               []*nmdata.Peer
	Network             *nmdata.Network
	Routes              []*nmdata.Route
	DNSConfig           nbdns.Config
	OfflinePeers        []*nmdata.Peer
	FirewallRules       []*FirewallRule
	RoutesFirewallRules []*RouteFirewallRule
	ForwardingRules     []*ForwardingRule
	AuthorizedUsers     map[string]map[string]struct{}
	EnableSSH           bool
	// ForceRoutingPeerDNSResolution forces the peer to run/use routing-peer DNS
	// resolution regardless of the account-global setting, for reverse-proxy
	// domain targets.
	ForceRoutingPeerDNSResolution bool
}

func (nm *NetworkMap) Merge(other *NetworkMap) {
	nm.Peers = mergeUniquePeersByID(nm.Peers, other.Peers)
	nm.Routes = mergeUnique(nm.Routes, other.Routes)
	nm.OfflinePeers = mergeUniquePeersByID(nm.OfflinePeers, other.OfflinePeers)
	nm.FirewallRules = mergeUnique(nm.FirewallRules, other.FirewallRules)
	nm.RoutesFirewallRules = mergeUnique(nm.RoutesFirewallRules, other.RoutesFirewallRules)
	nm.ForwardingRules = mergeUnique(nm.ForwardingRules, other.ForwardingRules)
	nm.ForceRoutingPeerDNSResolution = nm.ForceRoutingPeerDNSResolution || other.ForceRoutingPeerDNSResolution
}

func mergeUniquePeersByID(peers1, peers2 []*nmdata.Peer) []*nmdata.Peer {
	result := make(map[string]*nmdata.Peer)
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

type comparableObject[T any] interface {
	Equal(other T) bool
}

func mergeUnique[T comparableObject[T]](arr1, arr2 []T) []T {
	var result []T

	for _, item := range arr1 {
		if !containsEqual(result, item) {
			result = append(result, item)
		}
	}

	for _, item := range arr2 {
		if !containsEqual(result, item) {
			result = append(result, item)
		}
	}

	return result
}

func containsEqual[T comparableObject[T]](slice []T, element T) bool {
	for _, item := range slice {
		if item.Equal(element) {
			return true
		}
	}
	return false
}
