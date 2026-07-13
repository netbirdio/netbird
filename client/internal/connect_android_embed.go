//go:build android

package internal

import (
	"net/netip"

	"github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/client/internal/listener"
	"github.com/netbirdio/netbird/client/internal/stdnet"
)

// runOnAndroidEmbed is like RunOnAndroid but accepts a runningChan
// so embed.Client.Start() can detect when the engine is ready.
// It provides complete MobileDependency so the engine's existing
// Android code paths work unchanged.
func (c *ConnectClient) runOnAndroidEmbed(
	iFaceDiscover stdnet.ExternalIFaceDiscover,
	networkChangeListener listener.NetworkChangeListener,
	dnsAddresses []netip.AddrPort,
	dnsReadyListener dns.ReadyListener,
	runningChan chan struct{},
	logPath string,
) error {
	mobileDependency := MobileDependency{
		IFaceDiscover:         iFaceDiscover,
		NetworkChangeListener: networkChangeListener,
		HostDNSAddresses:      dnsAddresses,
		DnsReadyListener:      dnsReadyListener,
	}
	return c.run(mobileDependency, runningChan, logPath)
}
