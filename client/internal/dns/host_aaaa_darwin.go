//go:build !ios

package dns

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

// macOS only asks for AAAA records on a resolver when configd considers the
// resolver's network service routable for IPv6. NetBird publishes its match and
// search resolvers as DNS-only services, so on a host whose physical network has
// no global IPv6 (link-local only, or IPv4-only) the system resolver never asks
// for AAAA records of NetBird zones: applications resolving with AF_UNSPEC
// (browsers, RDP clients, ssh, ...) only get A records, although the overlay
// carries IPv6. ping6 works because it asks for AF_INET6 explicitly.
//
// Based on configd's IPMonitor (ip_plugin.c, dns-configuration.c):
//
//   - A service is routable for a family when its IPv4/IPv6 entity yields a
//     default route, i.e. carries a Router (or DestAddresses).
//   - get_dns_changes drops DNS server addresses of a family the service is not
//     routable for, so an IPv6-only entity would discard NetBird's IPv4 resolver
//     address and the whole resolver disappears. Both families are published.
//   - PrimaryRank Never keeps the defaults of these entities scoped to the
//     overlay interface (RTF_IFSCOPE), so the service never becomes primary and
//     the unscoped default stays on the physical interface. The network monitor
//     already ignores added scoped default routes.
//   - Services ranked Never are left out of the global resolver flags, so the DNS
//     entity carries ConfirmedServiceID. That makes the resolver a trusted
//     configuration bound to the overlay interface, which takes its A/AAAA flags
//     from its own service.
//
// Set NB_DNS_DISABLE_MACOS_AAAA=true to turn this off.

const (
	envDisableDarwinAAAA = "NB_DNS_DISABLE_MACOS_AAAA"

	// serviceStateKeyFormat is the configd key of a network service, entities
	// live below it as <key>/<entity>.
	serviceStateKeyFormat = "State:/Network/Service/%s"
	// netbirdServicePrefix is the prefix of every service ID NetBird publishes.
	netbirdServicePrefix = "NetBird-"

	entityDNS  = "DNS"
	entityIPv4 = "IPv4"
	entityIPv6 = "IPv6"

	// Service properties.
	keyPrimaryRank   = "PrimaryRank"
	primaryRankNever = "Never"

	// IPv4/IPv6 entity properties.
	keyInterfaceName = "InterfaceName"
	keyAddresses     = "Addresses"
	keySubnetMasks   = "SubnetMasks"
	keyPrefixLength  = "PrefixLength"
	keyRouter        = "Router"

	// DNS entity property marking the resolver as confirmed for its service.
	keyConfirmedServiceID = "ConfirmedServiceID"
)

// aaaaOverlay is the overlay interface and addresses published next to a
// NetBird resolver so that macOS requests AAAA records through it.
type aaaaOverlay struct {
	ifName string
	v4     netip.Prefix
	v6     netip.Prefix
}

func darwinAAAADisabled() bool {
	v, ok := os.LookupEnv(envDisableDarwinAAAA)
	if !ok {
		return false
	}
	disabled, err := strconv.ParseBool(v)
	if err != nil {
		log.Warnf("invalid value %q for %s, keeping macOS AAAA resolution enabled", v, envDisableDarwinAAAA)
		return false
	}
	return disabled
}

// aaaaOverlayFor returns the overlay to publish next to resolvers served on
// dnsServer, or nil when AAAA resolution through the overlay does not apply.
func (s *systemConfigurator) aaaaOverlayFor(dnsServer netip.Addr) *aaaaOverlay {
	if s.wgInterface == nil || darwinAAAADisabled() {
		return nil
	}
	// The resolver gets bound to the overlay interface, which only works while
	// NetBird's resolver is reached through it.
	if !dnsServer.IsValid() || dnsServer.IsLoopback() || dnsServer.IsUnspecified() {
		return nil
	}

	ifName := s.wgInterface.Name()
	addr := s.wgInterface.Address()
	if ifName == "" || !addr.IP.IsValid() || !addr.HasIPv6() {
		return nil
	}

	return &aaaaOverlay{
		ifName: ifName,
		v4:     addr.Prefix(),
		v6:     addr.IPv6Prefix(),
	}
}

func serviceStateKey(serviceID string) string {
	return fmt.Sprintf(serviceStateKeyFormat, serviceID)
}

func serviceEntityKey(serviceID, entity string) string {
	return serviceStateKey(serviceID) + "/" + entity
}

// serviceIDFromDNSKey returns the service ID of a NetBird DNS entity key, the
// <id> of State:/Network/Service/<id>/DNS. Keys of services NetBird does not
// own are rejected, so their entities are never touched.
func serviceIDFromDNSKey(key string) (string, bool) {
	prefix := serviceStateKey("")
	suffix := "/" + entityDNS
	if !strings.HasPrefix(key, prefix) || !strings.HasSuffix(key, suffix) {
		return "", false
	}
	id := strings.TrimSuffix(strings.TrimPrefix(key, prefix), suffix)
	if !strings.HasPrefix(id, netbirdServicePrefix) || strings.ContainsAny(id, "/ \t\n") {
		return "", false
	}
	return id, true
}

// buildSetStateCommands returns the scutil commands replacing key with a
// dictionary made of lines.
func buildSetStateCommands(key, lines string) string {
	return fmt.Sprintf("d.init\n%sset %s\n", lines, key)
}

// buildAAAAServiceCommands returns the scutil commands publishing the service
// rank and the IPv4/IPv6 entities of serviceID. The rank goes first so configd
// never evaluates the entities at the default rank. The router of each family
// is the overlay address itself, which keeps the routes on-link on the
// point-to-point interface.
func buildAAAAServiceCommands(serviceID string, o aaaaOverlay) string {
	rank := buildAddCommandLine(keyPrimaryRank, primaryRankNever)

	v4 := o.v4.Addr().String()
	ipv4 := buildAddCommandLine(keyInterfaceName, o.ifName)
	ipv4 += buildAddCommandLine(keyAddresses, arraySymbol+v4)
	ipv4 += buildAddCommandLine(keySubnetMasks, arraySymbol+net.IP(net.CIDRMask(o.v4.Bits(), 32)).String())
	ipv4 += buildAddCommandLine(keyRouter, v4)

	v6 := o.v6.Addr().String()
	ipv6 := buildAddCommandLine(keyInterfaceName, o.ifName)
	ipv6 += buildAddCommandLine(keyAddresses, arraySymbol+v6)
	ipv6 += buildAddCommandLine(keyPrefixLength, arraySymbol+digitSymbol+strconv.Itoa(o.v6.Bits()))
	ipv6 += buildAddCommandLine(keyRouter, v6)

	return buildSetStateCommands(serviceStateKey(serviceID), rank) +
		buildSetStateCommands(serviceEntityKey(serviceID, entityIPv4), ipv4) +
		buildSetStateCommands(serviceEntityKey(serviceID, entityIPv6), ipv6)
}

// buildAAAARemoveCommands returns the scutil commands removing what
// buildAAAAServiceCommands published. The address entities go first so configd
// drops the scoped routes before the rank. Removing keys that do not exist is
// harmless.
func buildAAAARemoveCommands(serviceID string) string {
	return buildRemoveKeyOperation(serviceEntityKey(serviceID, entityIPv4)) +
		buildRemoveKeyOperation(serviceEntityKey(serviceID, entityIPv6)) +
		buildRemoveKeyOperation(serviceStateKey(serviceID))
}
