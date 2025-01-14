package cmd

// Flag constants for system configuration
const (
	disableClientRoutesFlag = "disable-client-routes"
	disableServerRoutesFlag = "disable-server-routes"
	disableDNSFlag          = "disable-dns"
	disableFirewallFlag     = "disable-firewall"
)

var (
	disableClientRoutes bool
	disableServerRoutes bool
	disableDNS          bool
	disableFirewall     bool
)

func init() {
	// Add system flags to upCmd
	upCmd.PersistentFlags().BoolVar(&disableClientRoutes, disableClientRoutesFlag, false,
		"Disable client routes. If enabled, the client won't process client routes received from the management service.")

	upCmd.PersistentFlags().BoolVar(&disableServerRoutes, disableServerRoutesFlag, false,
		"Disable server routes. If enabled, the client won't act as a router for server routes received from the management service.")

	upCmd.PersistentFlags().BoolVar(&disableDNS, disableDNSFlag, false,
		"Disable DNS. If enabled, the client won't configure DNS settings.")

	upCmd.PersistentFlags().BoolVar(&disableFirewall, disableFirewallFlag, false,
		"Disable firewall configuration. If enabled, the client won't modify firewall rules.")
}
