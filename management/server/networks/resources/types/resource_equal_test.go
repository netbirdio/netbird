package types

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func baseEqualResource() *NetworkResource {
	return &NetworkResource{
		ID:          "res1",
		NetworkID:   "net1",
		AccountID:   "acc1",
		PublicID:    "pub1",
		Name:        "resource",
		Description: "desc",
		Type:        Subnet,
		Address:     "10.0.0.0/24",
		GroupIDs:    []string{"g1", "g2"},
		Prefix:      netip.MustParsePrefix("10.0.0.0/24"),
		Enabled:     true,
	}
}

func TestNetworkResourceEqual_Equal(t *testing.T) {
	a := baseEqualResource()
	b := baseEqualResource()
	b.PublicID = ""
	b.Address = ""
	b.GroupIDs = []string{"g2", "g1", "g2"}
	assert.True(t, a.Equal(b), "resources differing only in public ID, raw address and group order should be equal")
	assert.True(t, b.Equal(a), "comparison should be symmetric")
}

func TestNetworkResourceEqual_Differences(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(r *NetworkResource)
	}{
		{"id", func(r *NetworkResource) { r.ID = "res2" }},
		{"network", func(r *NetworkResource) { r.NetworkID = "net2" }},
		{"account", func(r *NetworkResource) { r.AccountID = "acc2" }},
		{"name", func(r *NetworkResource) { r.Name = "other" }},
		{"description", func(r *NetworkResource) { r.Description = "other" }},
		{"type", func(r *NetworkResource) { r.Type = Host }},
		{"prefix", func(r *NetworkResource) { r.Prefix = netip.MustParsePrefix("10.0.1.0/24") }},
		{"prefix host bits", func(r *NetworkResource) { r.Prefix = netip.MustParsePrefix("10.0.0.1/24") }},
		{"domain", func(r *NetworkResource) { r.Type = Domain; r.Domain = "example.com"; r.Prefix = netip.Prefix{} }},
		{"enabled", func(r *NetworkResource) { r.Enabled = false }},
		{"group removed", func(r *NetworkResource) { r.GroupIDs = []string{"g1"} }},
		{"group replaced", func(r *NetworkResource) { r.GroupIDs = []string{"g1", "g3"} }},
		{"group added", func(r *NetworkResource) { r.GroupIDs = []string{"g1", "g2", "g3"} }},
		{"groups cleared", func(r *NetworkResource) { r.GroupIDs = nil }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := baseEqualResource()
			b := baseEqualResource()
			tt.mutate(b)
			assert.False(t, a.Equal(b), "resources differing in %s should not be equal", tt.name)
			assert.False(t, b.Equal(a), "comparison should be symmetric for %s", tt.name)
		})
	}
}

func TestNetworkResourceEqual_NilAndEmpty(t *testing.T) {
	var nilResource *NetworkResource
	assert.True(t, nilResource.Equal(nil), "two nil resources should be equal")
	assert.False(t, baseEqualResource().Equal(nil), "a resource should not equal nil")
	assert.False(t, nilResource.Equal(baseEqualResource()), "nil should not equal a resource")

	a := &NetworkResource{ID: "res1", GroupIDs: nil}
	b := &NetworkResource{ID: "res1", GroupIDs: []string{}}
	assert.True(t, a.Equal(b), "nil and empty group IDs should be equal")
}
