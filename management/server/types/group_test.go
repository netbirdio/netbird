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
