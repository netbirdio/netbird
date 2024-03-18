package types

type NameServerGroup interface {
}

type DefaultNameServerGroup struct {
	// ID identifier of group
	ID string `gorm:"primaryKey"`
	// AccountID is a reference to Account that this object belongs
	AccountID string `gorm:"index"`
	// Name group name
	Name string
	// Description group description
	Description string
	// NameServers list of nameservers
	NameServers []NameServer `gorm:"serializer:json"`
	// Groups list of peer group IDs to distribute the nameservers information
	Groups []string `gorm:"serializer:json"`
	// Primary indicates that the nameserver group is the primary resolver for any dns query
	Primary bool
	// Domains indicate the dns query domains to use with this nameserver group
	Domains []string `gorm:"serializer:json"`
	// Enabled group status
	Enabled bool
	// SearchDomainsEnabled indicates whether to add match domains to search domains list or not
	SearchDomainsEnabled bool
}

// EventMeta returns activity event meta related to the nameserver group
func (g *DefaultNameServerGroup) EventMeta() map[string]any {
	return map[string]any{"name": g.Name}
}

// Copy copies a nameserver group object
func (g *DefaultNameServerGroup) Copy() *DefaultNameServerGroup {
	nsGroup := &DefaultNameServerGroup{
		ID:                   g.ID,
		Name:                 g.Name,
		Description:          g.Description,
		NameServers:          make([]NameServer, len(g.NameServers)),
		Groups:               make([]string, len(g.Groups)),
		Enabled:              g.Enabled,
		Primary:              g.Primary,
		Domains:              make([]string, len(g.Domains)),
		SearchDomainsEnabled: g.SearchDomainsEnabled,
	}

	copy(nsGroup.NameServers, g.NameServers)
	copy(nsGroup.Groups, g.Groups)
	copy(nsGroup.Domains, g.Domains)

	return nsGroup
}

// IsEqual compares one nameserver group with the other
func (g *DefaultNameServerGroup) IsEqual(other *DefaultNameServerGroup) bool {
	return other.ID == g.ID &&
		other.Name == g.Name &&
		other.Description == g.Description &&
		other.Primary == g.Primary &&
		other.SearchDomainsEnabled == g.SearchDomainsEnabled &&
		compareNameServerList(g.NameServers, other.NameServers) &&
		compareGroupsList(g.Groups, other.Groups) &&
		compareGroupsList(g.Domains, other.Domains)
}
