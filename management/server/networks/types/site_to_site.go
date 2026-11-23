package types

import (
	"github.com/netbirdio/netbird/shared/management/http/api"
)

// SiteToSiteConnection is a pair of networks joined by policies that let a resource in one of
// them reach a resource in the other.
type SiteToSiteConnection struct {
	// NetworkIDs holds the source network of the connection's first policy, then the other one.
	NetworkIDs [2]string
	PolicyIDs  []string
	Enabled    bool
}

// ToAPIResponse converts the connection to its API representation.
func (c *SiteToSiteConnection) ToAPIResponse() *api.SiteToSiteConnection {
	return &api.SiteToSiteConnection{
		NetworkIds: []string{c.NetworkIDs[0], c.NetworkIDs[1]},
		PolicyIds:  append([]string{}, c.PolicyIDs...),
		Enabled:    c.Enabled,
	}
}
