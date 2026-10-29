package manager

import (
	"context"
	"time"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/activity"
	"github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

// peerSeenInterval is how stale a peer's LastSeen must be before reaching a
// private service refreshes it. Positive tunnel validations are cached on the
// proxy for five minutes, so without a floor a busy peer would rewrite its row
// behind every request; an hour still sits well inside the window activity
// accounting asks about.
const peerSeenInterval = time.Hour

type managerImpl struct {
	store store.Store
}

// NewManager returns the activity manager backed by the management store.
func NewManager(store store.Store) activity.Manager {
	return &managerImpl{store: store}
}

// RecordUserLogin stamps the login the same way the dashboard and device login
// paths do, so a person who only ever reaches proxied services still has a
// login on record.
func (m *managerImpl) RecordUserLogin(ctx context.Context, accountID string, user *types.User) error {
	if user == nil || user.IsServiceUser {
		return nil
	}

	return m.store.SaveUserLastLogin(ctx, accountID, user.Id, time.Now().UTC())
}

// RecordPeerSeen stamps LastSeen, the column a peer activates its owner
// through. The peer the caller already holds answers the throttle without a
// query, so a peer seen inside the interval costs nothing to skip; the same
// cutoff goes to the store, which enforces it inside the UPDATE so concurrent
// requests for one peer cannot each write off their own stale read.
func (m *managerImpl) RecordPeerSeen(ctx context.Context, accountID string, peer *peer.Peer) error {
	if peer == nil || !countsTowardActivity(peer) {
		return nil
	}

	staleBefore := time.Now().UTC().Add(-peerSeenInterval)
	if peer.Status != nil && peer.Status.LastSeen.After(staleBefore) {
		return nil
	}

	_, err := m.store.RefreshPeerLastSeen(ctx, accountID, peer.ID, staleBefore)

	return err
}

// countsTowardActivity reports whether the peer represents a device a person
// actually runs. Embedded proxy peers are infrastructure and browser (WASM)
// clients are ephemeral sessions, so activity accounting ignores both and a
// write for them could never count.
func countsTowardActivity(peer *peer.Peer) bool {
	return !peer.ProxyMeta.Embedded && peer.Meta.KernelVersion != "wasm"
}
