package cmd

// Flag constants for system configuration
const (
	disableClientRoutesFlag  = "disable-client-routes"
	disableServerRoutesFlag  = "disable-server-routes"
	disableDefaultRouteFlag  = "disable-default-route"
	disableDNSFlag           = "disable-dns"
	disableFirewallFlag      = "disable-firewall"
	blockLANAccessFlag       = "block-lan-access"
	blockInboundFlag         = "block-inbound"
)

var (
	disableClientRoutes bool
	disableServerRoutes bool
	disableDefaultRoute bool
	disableDNS          bool
	disableFirewall     bool
	blockLANAccess      bool
	blockInbound        bool
)

func init() {
	// Add system flags to upCmd
	upCmd.PersistentFlags().BoolVar(&disableClientRoutes, disableClientRoutesFlag, false,
		"Disable client routes. If enabled, the client won't process client routes received from the management service.")

	upCmd.PersistentFlags().BoolVar(&disableServerRoutes, disableServerRoutesFlag, false,
		"Disable server routes. If enabled, the client won't act as a router for server routes received from the management service.")

	upCmd.PersistentFlags().BoolVar(&disableDefaultRoute, disableDefaultRouteFlag, false,
		"Disable adding default route (0.0.0.0/0) to the system routing table while keeping it in WireGuard allowed IPs.")

	upCmd.PersistentFlags().BoolVar(&disableDNS, disableDNSFlag, false,
		"Disable DNS. If enabled, the client won't configure DNS settings.")

	upCmd.PersistentFlags().BoolVar(&disableFirewall, disableFirewallFlag, false,
		"Disable firewall configuration. If enabled, the client won't modify firewall rules.")

	upCmd.PersistentFlags().BoolVar(&blockLANAccess, blockLANAccessFlag, false,
		"Block access to local networks (LAN) when using this peer as a router or exit node")

	upCmd.PersistentFlags().BoolVar(&blockInbound, blockInboundFlag, false,
		"Block inbound connections. If enabled, the client will not allow any inbound connections to the local machine nor routed networks.\n"+
			"This overrides any policies received from the management service.")
}
