package store

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/relay/messages"
)

const storeWaitTimeout = 2 * time.Second

type MocPeer struct {
	id            messages.PeerID
	authenticated bool
	closed        bool
}

type blockingPeer struct {
	id      messages.PeerID
	entered chan struct{}
	release chan struct{}
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

func (p *blockingPeer) Close() {
	close(p.entered)
	<-p.release
}

func (p *blockingPeer) Authenticated() bool {
	return false
}

func (p *blockingPeer) ID() messages.PeerID {
	return p.id
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

func TestStore_AddPeerClosesReplacedPeerOutsideLock(t *testing.T) {
	s := NewStore()

	id := messages.HashID("peer_one")
	old := &blockingPeer{id: id, entered: make(chan struct{}), release: make(chan struct{})}
	releaseOld := sync.OnceFunc(func() { close(old.release) })
	t.Cleanup(releaseOld)
	replacement := &MocPeer{id: id}
	_, err := s.AddPeer(old)
	require.NoError(t, err)

	replaced := make(chan bool, 1)
	go func() {
		ok, _ := s.AddPeer(replacement)
		replaced <- ok
	}()
	select {
	case <-old.entered:
	case <-time.After(storeWaitTimeout):
		require.Fail(t, "the replaced peer must be closed")
	}

	stored := make(chan IPeer, 1)
	go func() {
		p, _ := s.Peer(id)
		bystander := &MocPeer{id: messages.HashID("bystander")}
		_, _ = s.AddPeer(bystander)
		s.DeletePeer(bystander)
		stored <- p
	}()
	select {
	case p := <-stored:
		assert.Same(t, replacement, p, "the replacement must be stored before the old peer is closed")
	case <-time.After(storeWaitTimeout):
		assert.Fail(t, "the store must stay usable while a replaced peer is closing")
	}

	releaseOld()
	select {
	case wasReplaced := <-replaced:
		assert.True(t, wasReplaced, "replacing a peer must be reported")
	case <-time.After(storeWaitTimeout):
		assert.Fail(t, "adding the peer must finish once the replaced peer is closed")
	}
}
