package routemanager

type firewallManager interface {
	RestoreOrCreateContainers() error
	InsertRoutingRules(pair RouterPair) error
	RemoveRoutingRules(pair RouterPair) error
	CleanRoutingRules()
}
