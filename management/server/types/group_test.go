package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddPeer(t *testing.T) {
	t.Run("add new peer to empty slice", func(t *testing.T) {
		group := &Group{Peers: []string{}}
		peerID := "peer1"
		assert.True(t, group.AddPeer(peerID))
		assert.Contains(t, group.Peers, peerID)
	})

	t.Run("add new peer to nil slice", func(t *testing.T) {
		group := &Group{Peers: nil}
		peerID := "peer1"
		assert.True(t, group.AddPeer(peerID))
		assert.Contains(t, group.Peers, peerID)
	})

	t.Run("add new peer to non-empty slice", func(t *testing.T) {
		group := &Group{Peers: []string{"peer1", "peer2"}}
		peerID := "peer3"
		assert.True(t, group.AddPeer(peerID))
		assert.Contains(t, group.Peers, peerID)
	})

	t.Run("add duplicate peer", func(t *testing.T) {
		group := &Group{Peers: []string{"peer1", "peer2"}}
		peerID := "peer1"
		assert.False(t, group.AddPeer(peerID))
		assert.Equal(t, 2, len(group.Peers))
	})

	t.Run("add empty peer", func(t *testing.T) {
		group := &Group{Peers: []string{"peer1", "peer2"}}
		peerID := ""
		assert.False(t, group.AddPeer(peerID))
		assert.Equal(t, 2, len(group.Peers))
	})
}

func TestRemovePeer(t *testing.T) {
	t.Run("remove existing peer from slice", func(t *testing.T) {
		group := &Group{Peers: []string{"peer1", "peer2", "peer3"}}
		peerID := "peer2"
		assert.True(t, group.RemovePeer(peerID))
		assert.NotContains(t, group.Peers, peerID)
		assert.Equal(t, 2, len(group.Peers))
	})

	t.Run("remove peer from empty slice", func(t *testing.T) {
		group := &Group{Peers: []string{}}
		peerID := "peer1"
		assert.False(t, group.RemovePeer(peerID))
		assert.Equal(t, 0, len(group.Peers))
	})

	t.Run("remove peer from nil slice", func(t *testing.T) {
		group := &Group{Peers: nil}
		peerID := "peer1"
		assert.False(t, group.RemovePeer(peerID))
		assert.Nil(t, group.Peers)
	})

	t.Run("remove non-existent peer", func(t *testing.T) {
		group := &Group{Peers: []string{"peer1", "peer2"}}
		peerID := "peer3"
		assert.False(t, group.RemovePeer(peerID))
		assert.Equal(t, 2, len(group.Peers))
	})

	t.Run("remove peer from single-item slice", func(t *testing.T) {
		group := &Group{Peers: []string{"peer1"}}
		peerID := "peer1"
		assert.True(t, group.RemovePeer(peerID))
		assert.Equal(t, 0, len(group.Peers))
		assert.NotContains(t, group.Peers, peerID)
	})

	t.Run("remove empty peer", func(t *testing.T) {
		group := &Group{Peers: []string{"peer1", "peer2"}}
		peerID := ""
		assert.False(t, group.RemovePeer(peerID))
		assert.Equal(t, 2, len(group.Peers))
	})
}

func TestGroupEqual(t *testing.T) {
	base := &Group{
		ID:        "g1",
		AccountID: "acc",
		Name:      "group",
		Issued:    GroupIssuedAPI,
		Peers:     []string{"p1", "p2"},
		Resources: []Resource{{ID: "r1", Type: ResourceType("host")}, {ID: "r2", Type: ResourceType("domain")}},
	}

	reordered := base.Copy()
	reordered.Peers = []string{"p2", "p1"}
	reordered.Resources = []Resource{{ID: "r2", Type: ResourceType("domain")}, {ID: "r1", Type: ResourceType("host")}}
	reordered.PublicID = "different"
	assert.True(t, base.Equal(reordered), "order of peers/resources and public ID should not matter")

	tests := map[string]func(g *Group){
		"name":        func(g *Group) { g.Name = "other" },
		"issued":      func(g *Group) { g.Issued = GroupIssuedJWT },
		"peer added":  func(g *Group) { g.Peers = append(g.Peers, "p3") },
		"peer swap":   func(g *Group) { g.Peers = []string{"p1", "p3"} },
		"resource":    func(g *Group) { g.Resources = g.Resources[:1] },
		"res type":    func(g *Group) { g.Resources[0].Type = ResourceType("subnet") },
		"integration": func(g *Group) { g.IntegrationReference.ID = 7 },
		"account":     func(g *Group) { g.AccountID = "other" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			changed := base.Copy()
			mutate(changed)
			assert.False(t, base.Equal(changed), "groups differing by %s should not be equal", name)
		})
	}

	assert.True(t, (*Group)(nil).Equal(nil), "two nil groups should be equal")
	assert.False(t, base.Equal(nil), "group should not equal nil")
}
