package routemanager

type firewallManager interface {
	// RestoreOrCreateContainers restores or creates a firewall container set of rules, tables and default rules
	RestoreOrCreateContainers() error
	// InsertRoutingRules inserts a routing firewall rule
	InsertRoutingRules(pair routerPair) error
	// RemoveRoutingRules removes a routing firewall rule
	RemoveRoutingRules(pair routerPair) error
	// CleanRoutingRules cleans a firewall set of containers
	CleanRoutingRules()
}
