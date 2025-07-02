package cmd

// Flag constants for system configuration
const (
	disableClientRoutesFlag = "disable-client-routes"
	disableServerRoutesFlag = "disable-server-routes"
	disableDNSFlag          = "disable-dns"
	disableFirewallFlag     = "disable-firewall"
	blockLANAccessFlag      = "block-lan-access"
	blockInboundFlag        = "block-inbound"
)

var (
	disableClientRoutes bool
	disableServerRoutes bool
	disableDNS          bool
	disableFirewall     bool
	blockLANAccess      bool
	blockInbound        bool
)

