package integrated_validator

import (
	"context"

	"github.com/netbirdio/netbird/management/server/account"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
)

// IntegratedValidator interface exists to avoid the circle dependencies
type IntegratedValidator interface {
	ValidateExtraSettings(ctx context.Context, newExtraSettings *account.ExtraSettings, oldExtraSettings *account.ExtraSettings, peers map[string]*nbpeer.Peer, userID string, accountID string) error
	ValidatePeer(ctx context.Context, update *nbpeer.Peer, peer *nbpeer.Peer, userID string, accountID string, dnsDomain string, peersGroup []string, extraSettings *account.ExtraSettings) (*nbpeer.Peer, bool, error)
	PreparePeer(ctx context.Context, accountID string, peer *nbpeer.Peer, peersGroup []string, extraSettings *account.ExtraSettings) *nbpeer.Peer
	IsNotValidPeer(ctx context.Context, accountID string, peer *nbpeer.Peer, peersGroup []string, extraSettings *account.ExtraSettings) (bool, bool, error)
	GetValidatedPeers(accountID string, groups []*types.Group, peers []*nbpeer.Peer, extraSettings *account.ExtraSettings) (map[string]struct{}, error)
	PeerDeleted(ctx context.Context, accountID, peerID string) error
	SetPeerInvalidationListener(fn func(accountID string))
	Stop(ctx context.Context)
}
