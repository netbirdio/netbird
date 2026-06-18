//go:build android

package internal

import (
	"net/netip"

	"github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/client/internal/listener"
	"github.com/netbirdio/netbird/client/internal/stdnet"
)

// mobileDependencyForEmbed builds the MobileDependency used by embed.Client on
// Android so the engine's existing Android code paths work unchanged.
func mobileDependencyForEmbed(
	iFaceDiscover stdnet.ExternalIFaceDiscover,
	networkChangeListener listener.NetworkChangeListener,
	dnsAddresses []netip.AddrPort,
	dnsReadyListener dns.ReadyListener,
) MobileDependency {
	return MobileDependency{
		IFaceDiscover:         iFaceDiscover,
		NetworkChangeListener: networkChangeListener,
		HostDNSAddresses:      dnsAddresses,
		DnsReadyListener:      dnsReadyListener,
	}
}
