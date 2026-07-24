package types

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"slices"
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
	// AllowedIPsV6Format generates AllowedIPs format for v6 (e.g. fd12:3456:7890::1/128)
	AllowedIPsV6Format = "%s/128"

	// IPv6SubnetSize is the prefix length of per-account IPv6 subnets.
	// Each account gets a /64 from its unique /48 ULA prefix.
	IPv6SubnetSize = 64
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
	// NetV6 is the IPv6 ULA subnet for this account's overlay. Empty if not yet allocated.
	NetV6 net.IPNet `gorm:"serializer:json"`
	Dns   string
	// Serial is an ID that increments by 1 when any change to the network happened (e.g. new peer has been added).
	// Used to synchronize state to the client apps.
	Serial uint64

	Mu sync.Mutex `json:"-" gorm:"-"`
}

// NewNetwork creates a new Network initializing it with a Serial=0
// It takes a random /16 subnet from 100.64.0.0/10 (64 different subnets)
// and a random /64 subnet from fd00:4e42::/32 for IPv6.
func NewNetwork() *Network {
	n := iplib.NewNet4(net.ParseIP("100.64.0.0"), NetSize)
	sub, _ := n.Subnet(SubnetSize)

	s := rand.NewSource(time.Now().UnixNano())
	r := rand.New(s)
	intn := r.Intn(len(sub))

	return &Network{
		Identifier: xid.New().String(),
		Net:        sub[intn].IPNet,
		NetV6:      AllocateIPv6Subnet(r),
		Dns:        "",
		Serial:     0,
	}
}

// AllocateIPv6Subnet generates a random RFC 4193 ULA /64 prefix.
// The format follows RFC 4193 section 3.1: fd + 40-bit Global ID + 16-bit Subnet ID.
// The Global ID and Subnet ID are randomized (simplified from the SHA-1 algorithm
// in section 3.2.2), giving 2^56 possible /64 subnets across all accounts.
func AllocateIPv6Subnet(r *rand.Rand) net.IPNet {
	ip := make(net.IP, 16)
	ip[0] = 0xfd
	// Bytes 1-5: 40-bit random Global ID
	ip[1] = byte(r.Intn(256))
	ip[2] = byte(r.Intn(256))
	ip[3] = byte(r.Intn(256))
	ip[4] = byte(r.Intn(256))
	ip[5] = byte(r.Intn(256))
	// Bytes 6-7: 16-bit random Subnet ID
	ip[6] = byte(r.Intn(256))
	ip[7] = byte(r.Intn(256))

	return net.IPNet{
		IP:   ip,
		Mask: net.CIDRMask(IPv6SubnetSize, 128),
	}
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
	n.Mu.Lock()
	defer n.Mu.Unlock()
	return &Network{
		Identifier: n.Identifier,
		Net:        n.Net,
		NetV6:      n.NetV6,
		Dns:        n.Dns,
		Serial:     n.Serial,
	}
}

// AllocatePeerIP picks an available IP from a netip.Prefix.
// This method considers already taken IPs and reuses IPs if there are gaps in takenIps.
// E.g. if prefix=100.30.0.0/16 and takenIps=[100.30.0.1, 100.30.0.4] then the result would be 100.30.0.2 or 100.30.0.3.
func AllocatePeerIP(prefix netip.Prefix, takenIps []netip.Addr) (netip.Addr, error) {
	b := prefix.Masked().Addr().As4()
	baseIP := binary.BigEndian.Uint32(b[:])
	hostBits := 32 - prefix.Bits()
	totalIPs := uint32(1 << hostBits)

	taken := make(map[uint32]struct{}, len(takenIps)+1)
	taken[baseIP] = struct{}{}            // reserve network IP
	taken[baseIP+totalIPs-1] = struct{}{} // reserve broadcast IP

	for _, ip := range takenIps {
		ab := ip.As4()
		taken[binary.BigEndian.Uint32(ab[:])] = struct{}{}
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

	return netip.Addr{}, status.Errorf(status.PreconditionFailed, "network %s is out of IPs", prefix.String())
}

// AllocateRandomPeerIP picks a random available IP from a netip.Prefix.
func AllocateRandomPeerIP(prefix netip.Prefix) (netip.Addr, error) {
	b := prefix.Masked().Addr().As4()
	baseIP := binary.BigEndian.Uint32(b[:])
	hostBits := 32 - prefix.Bits()
	totalIPs := uint32(1 << hostBits)

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	offset := uint32(rng.Intn(int(totalIPs-2))) + 1

	candidate := baseIP + offset
	return uint32ToIP(candidate), nil
}

// AllocateRandomPeerIPv6 picks a random host address within the given IPv6 prefix.
// Only the host bits (after the prefix length) are randomized.
func AllocateRandomPeerIPv6(prefix netip.Prefix) (netip.Addr, error) {
	ones := prefix.Bits()
	if ones == 0 || ones > 126 || !prefix.Addr().Is6() {
		return netip.Addr{}, fmt.Errorf("invalid IPv6 subnet: %s", prefix.String())
	}

	ip := prefix.Addr().As16()

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	// Determine which byte the host bits start in
	firstHostByte := ones / 8
	// If the prefix doesn't end on a byte boundary, handle the partial byte
	partialBits := ones % 8

	if partialBits > 0 {
		// Keep the network bits in the partial byte, randomize the rest
		hostMask := byte(0xff >> partialBits)
		ip[firstHostByte] = (ip[firstHostByte] & ^hostMask) | (byte(rng.Intn(256)) & hostMask)
		firstHostByte++
	}

	// Randomize remaining full host bytes
	for i := firstHostByte; i < 16; i++ {
		ip[i] = byte(rng.Intn(256))
	}

	// Avoid all-zeros and all-ones host parts by checking only host bits.
	if isHostAllZeroOrOnes(ip[:], ones) {
		ip = prefix.Masked().Addr().As16()
		ip[15] |= 0x01
	}

	return netip.AddrFrom16(ip).Unmap(), nil
}

// isHostAllZeroOrOnes checks whether all host bits (after prefixLen) are zero or all ones.
func isHostAllZeroOrOnes(ip []byte, prefixLen int) bool {
	hostStart := prefixLen / 8
	partialBits := prefixLen % 8

	hostSlice := slices.Clone(ip[hostStart:])
	if partialBits > 0 {
		hostSlice[0] &= 0xff >> partialBits
	}

	allZero := !slices.ContainsFunc(hostSlice, func(v byte) bool { return v != 0 })
	if allZero {
		return true
	}

	// Build the all-ones mask for host bits
	onesMask := make([]byte, len(hostSlice))
	for i := range onesMask {
		onesMask[i] = 0xff
	}
	if partialBits > 0 {
		onesMask[0] = 0xff >> partialBits
	}

	return slices.Equal(hostSlice, onesMask)
}

func uint32ToIP(n uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], n)
	return netip.AddrFrom4(b)
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
