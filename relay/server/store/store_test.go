package store

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/relay/messages"
)

type MocPeer struct {
	id            messages.PeerID
	authenticated bool
	closed        bool
}

func (m *MocPeer) Close() {
	m.closed = true
}

func (m *MocPeer) Authenticated() bool {
	return m.authenticated
}

func (m *MocPeer) ID() messages.PeerID {
	return m.id
}

func TestStore_DeletePeer(t *testing.T) {
	s := NewStore()

	pID := messages.HashID("peer_one")
	p := &MocPeer{id: pID}
	_, _ = s.AddPeer(p)
	s.DeletePeer(p)
	if _, ok := s.Peer(pID); ok {
		t.Errorf("peer was not deleted")
	}
}

func TestStore_DeleteDeprecatedPeer(t *testing.T) {
	s := NewStore()

	pID1 := messages.HashID("peer_one")
	pID2 := messages.HashID("peer_one")

	p1 := &MocPeer{id: pID1}
	p2 := &MocPeer{id: pID2}

	_, _ = s.AddPeer(p1)
	_, _ = s.AddPeer(p2)
	s.DeletePeer(p1)

	if _, ok := s.Peer(pID2); !ok {
		t.Errorf("second peer was deleted")
	}
}

func TestStore_AuthenticatedPeerIsNotTakenOver(t *testing.T) {
	id := messages.HashID("peer_one")

	tests := []struct {
		name                               string
		oldAuthenticated, newAuthenticated bool
		wantReplaced                       bool
	}{
		{"legacy replaces legacy", false, false, true},
		{"authenticated replaces legacy", false, true, true},
		{"authenticated replaces authenticated", true, true, true},
		{"legacy cannot replace authenticated", true, false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := NewStore()
			oldPeer := &MocPeer{id: id, authenticated: tc.oldAuthenticated}
			newPeer := &MocPeer{id: id, authenticated: tc.newAuthenticated}
			_, err := s.AddPeer(oldPeer)
			require.NoError(t, err)

			replaced, err := s.AddPeer(newPeer)
			stored, _ := s.Peer(id)
			if !tc.wantReplaced {
				assert.ErrorIs(t, err, ErrAuthenticatedPeerExists)
				assert.Same(t, oldPeer, stored, "the authenticated peer must stay")
				assert.False(t, oldPeer.closed, "the authenticated peer must not be closed")
				return
			}
			require.NoError(t, err)
			assert.True(t, replaced, "the second peer is a reconnection")
			assert.Same(t, newPeer, stored, "the new peer must replace the old one")
			assert.True(t, oldPeer.closed, "the replaced peer must be closed")
		})
	}
}
