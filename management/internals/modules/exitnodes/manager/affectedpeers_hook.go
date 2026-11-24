package manager

import (
	"context"

	"github.com/netbirdio/netbird/management/internals/shared/db"
	"github.com/netbirdio/netbird/management/server/affectedpeers"
	"github.com/netbirdio/netbird/management/server/store"
)

// init registers the exit node routing peers with the affected peers resolver, so a
// policy change that targets an exit node also refreshes the peers routing for it.
// Registered here, rather than imported by affectedpeers, to avoid an import cycle
// (manager → account → affectedpeers).
func init() {
	affectedpeers.SetExitNodeRoutingPeers(routingPeersByExitNode)
}

// connStore is a store whose connection and bound transaction exit nodes can be read
// through.
type connStore interface {
	Conn() *db.Conn
	Tx() *db.Tx
}

// routingPeersByExitNode reads the exit nodes through the store's own transaction: the
// resolver loads inside the caller's transaction, and reading on another connection
// while it is open blocks on a single-connection database.
func routingPeersByExitNode(ctx context.Context, s store.Store, accountID string) (map[string][]string, error) {
	cs, ok := s.(connStore)
	if !ok {
		return map[string][]string{}, nil
	}

	nodes, err := NewRepository(cs.Conn()).WithTx(cs.Tx()).ListByAccount(ctx, db.LockingStrengthNone, accountID)
	if err != nil {
		return nil, err
	}

	peers := make(map[string][]string, len(nodes))
	for _, node := range nodes {
		if ids := node.RoutingPeerIDs(); len(ids) > 0 {
			peers[string(node.ID)] = ids
		}
	}
	return peers, nil
}
