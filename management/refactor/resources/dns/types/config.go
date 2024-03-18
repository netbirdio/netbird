package types

// Config represents a dns configuration that is exchanged between management and peers
type Config struct {
	// ServiceEnable indicates if the service should be enabled
	ServiceEnable bool
	// NameServerGroups contains a list of nameserver group
	NameServerGroups []*NameServerGroup
	// CustomZones contains a list of custom zone
	CustomZones []CustomZone
}
