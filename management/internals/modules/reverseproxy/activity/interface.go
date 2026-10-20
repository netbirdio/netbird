// Package activity records that a principal used a reverse proxy service, so
// that activity accounting counts people and devices which reach services
// through the proxy but never touch the dashboard or the management API.
package activity

import (
	"context"

	"github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
)

// Manager records reverse proxy usage against the timestamps activity
// accounting reads. Both methods are best effort from the caller's point of
// view: a lost record is corrected by the next request, and no authorization
// decision reads them back.
type Manager interface {
	// RecordUserLogin records a completed SSO sign-in to a proxied service.
	// Service users have no interactive login and are ignored.
	RecordUserLogin(ctx context.Context, accountID string, user *types.User) error
	// RecordPeerSeen records that a peer reached a private service over the
	// mesh, which is what lets its owner count as active. Peers activity
	// accounting excludes, and peers already seen recently, are ignored.
	RecordPeerSeen(ctx context.Context, accountID string, peer *peer.Peer) error
}
