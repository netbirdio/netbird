package types

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/shared/management/integration_reference"
)

func baseEqualGroup() *Group {
	return &Group{
		ID:        "g1",
		AccountID: "acc1",
		PublicID:  "pub1",
		Name:      "group",
		Issued:    GroupIssuedAPI,
		Peers:     []string{"p1", "p2"},
		Resources: []Resource{
			{ID: "r1", Type: ResourceTypeHost},
			{ID: "r2", Type: ResourceTypeSubnet},
		},
		IntegrationReference: integration_reference.IntegrationReference{ID: 1, IntegrationType: "okta"},
	}
}

func TestGroupEqualIgnoringPeers_Equal(t *testing.T) {
	a := baseEqualGroup()
	b := baseEqualGroup()
	b.Peers = []string{"p3"}
	b.PublicID = ""
	b.Resources = []Resource{b.Resources[1], b.Resources[0]}
	assert.True(t, a.EqualIgnoringPeers(b), "groups differing only in peers, public ID and resource order should be equal")
}

func TestGroupEqualIgnoringPeers_Differences(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(g *Group)
	}{
		{"id", func(g *Group) { g.ID = "g2" }},
		{"account", func(g *Group) { g.AccountID = "acc2" }},
		{"name", func(g *Group) { g.Name = "other" }},
		{"issued", func(g *Group) { g.Issued = GroupIssuedJWT }},
		{"integration id", func(g *Group) { g.IntegrationReference.ID = 2 }},
		{"integration type", func(g *Group) { g.IntegrationReference.IntegrationType = "azure" }},
		{"resource removed", func(g *Group) { g.Resources = g.Resources[:1] }},
		{"resource type", func(g *Group) { g.Resources[0].Type = ResourceTypeDomain }},
		{"resource id", func(g *Group) { g.Resources[0].ID = "r3" }},
		{"resource duplicated", func(g *Group) { g.Resources = []Resource{g.Resources[0], g.Resources[0]} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := baseEqualGroup()
			b := baseEqualGroup()
			tt.mutate(b)
			assert.False(t, a.EqualIgnoringPeers(b), "groups differing in %s should not be equal", tt.name)
			assert.False(t, b.EqualIgnoringPeers(a), "comparison should be symmetric for %s", tt.name)
		})
	}
}

func TestGroupEqualIgnoringPeers_NilAndEmpty(t *testing.T) {
	var nilGroup *Group
	assert.True(t, nilGroup.EqualIgnoringPeers(nil), "two nil groups should be equal")
	assert.False(t, baseEqualGroup().EqualIgnoringPeers(nil), "a group should not equal nil")
	assert.False(t, nilGroup.EqualIgnoringPeers(baseEqualGroup()), "nil should not equal a group")

	a := &Group{ID: "g1", Resources: nil}
	b := &Group{ID: "g1", Resources: []Resource{}}
	assert.True(t, a.EqualIgnoringPeers(b), "nil and empty resources should be equal")
}
