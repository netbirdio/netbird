//go:build android

package internal

import (
	"net/netip"

	"github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/client/internal/listener"
	"github.com/netbirdio/netbird/client/internal/stdnet"
)

// noopIFaceDiscover is a stub ExternalIFaceDiscover for embed.Client on Android.
// It returns an empty interface list, which means ICE P2P candidates won't be
// discovered — connections will fall back to relay. Applications that need P2P
// should provide a real implementation via runOnAndroidEmbed that uses
// Android's ConnectivityManager to enumerate network interfaces.
type noopIFaceDiscover struct{}

func (noopIFaceDiscover) IFaces() (string, error) {
	// Return empty JSON array — no local interfaces advertised for ICE.
	// This is intentional: without Android's ConnectivityManager, we cannot
	// reliably enumerate interfaces (netlink is restricted on Android 11+).
	// Relay connections still work; only P2P hole-punching is disabled.
	return "[]", nil
}

// noopNetworkChangeListener is a stub for embed.Client on Android.
// Network change events are ignored since the embed client manages its own
// reconnection logic via the engine's built-in retry mechanism.
type noopNetworkChangeListener struct{}

func (noopNetworkChangeListener) OnNetworkChanged(string) {
	// No-op: embed.Client relies on the engine's internal reconnection
	// logic rather than OS-level network change notifications.
}

func (noopNetworkChangeListener) SetInterfaceIP(string) {
	// No-op: in netstack mode, the overlay IP is managed by the userspace
	// network stack, not by OS-level interface configuration.
}

// noopDnsReadyListener is a stub for embed.Client on Android.
// DNS readiness notifications are not needed in netstack/embed mode
// since system DNS is disabled and DNS resolution happens externally.
type noopDnsReadyListener struct{}

func (noopDnsReadyListener) OnReady() {
	// No-op: embed.Client does not need DNS readiness notifications.
	// System DNS is disabled in netstack mode.
}

var _ stdnet.ExternalIFaceDiscover = noopIFaceDiscover{}
var _ listener.NetworkChangeListener = noopNetworkChangeListener{}
var _ dns.ReadyListener = noopDnsReadyListener{}

func init() {
	// Wire up the default override so embed.Client.Start() works on Android
	// with netstack mode. Provides complete no-op stubs for all mobile
	// dependencies so the engine's existing Android code paths work unchanged.
	// Applications that need P2P ICE or real DNS should replace this by
	// setting androidRunOverride before calling Start().
	androidRunOverride = func(c *ConnectClient, runningChan chan struct{}, logPath string) error {
		return c.runOnAndroidEmbed(
			noopIFaceDiscover{},
			noopNetworkChangeListener{},
			[]netip.AddrPort{},
			noopDnsReadyListener{},
			runningChan,
			logPath,
		)
	}
}
