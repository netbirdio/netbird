package internal

import (
	"net/netip"

	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/client/internal/listener"
	"github.com/netbirdio/netbird/client/internal/stdnet"
)

// MobileDependency collect all dependencies for mobile platform
type MobileDependency struct {
	// Android only
	TunAdapter            device.TunAdapter
	IFaceDiscover         stdnet.ExternalIFaceDiscover
	NetworkChangeListener listener.NetworkChangeListener
	HostDNSAddresses      []netip.AddrPort
	DnsReadyListener      dns.ReadyListener

	//	iOS only
	DnsManager     dns.IosDnsManager
	FileDescriptor int32
	StateFilePath  string

	// TempDir is a writable directory for temporary files (e.g., debug bundle zip).
	// On Android, this should be set to the app's cache directory.
	TempDir string
}
