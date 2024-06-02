package group

import "github.com/netbirdio/netbird/management/server/integration_reference"

const (
	GroupIssuedAPI         = "api"
	GroupIssuedJWT         = "jwt"
	GroupIssuedIntegration = "integration"
)

// Group of the peers for ACL
type Group struct {
	// ID of the group
	ID string

	// AccountID is a reference to Account that this object belongs
	AccountID string `json:"-" gorm:"index"`

	// Name visible in the UI
	Name string

	// Issued defines how this group was created (enum of "api", "integration" or "jwt")
	Issued string

	// Peers list of the group
	Peers []string `gorm:"serializer:json"`

	IPv6Enabled bool

	IntegrationReference integration_reference.IntegrationReference `gorm:"embedded;embeddedPrefix:integration_ref_"`
}

// EventMeta returns activity event meta related to the group
func (g *Group) EventMeta() map[string]any {
	return map[string]any{"name": g.Name}
}

func (g *Group) Copy() *Group {
	group := &Group{
		ID:                   g.ID,
		Name:                 g.Name,
		Issued:               g.Issued,
		IPv6Enabled:          g.IPv6Enabled,
		Peers:                make([]string, len(g.Peers)),
		IntegrationReference: g.IntegrationReference,
	}
	copy(group.Peers, g.Peers)
	return group
}
