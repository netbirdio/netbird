package integrated_validator

import (
	"context"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// IntegratedValidator interface exists to avoid the circle dependencies
type IntegratedValidator interface {
	ValidateExtraSettings(ctx context.Context, newExtraSettings *types.ExtraSettings, oldExtraSettings *types.ExtraSettings, peers map[string]*nbpeer.Peer, userID string, accountID string) error
	ValidatePeer(ctx context.Context, update *nbpeer.Peer, peer *nbpeer.Peer, userID string, accountID string, dnsDomain string, peersGroup []string, extraSettings *types.ExtraSettings) (*nbpeer.Peer, bool, error)
	PreparePeer(ctx context.Context, accountID string, peer *nbpeer.Peer, peersGroup []string, extraSettings *types.ExtraSettings) *nbpeer.Peer
	IsNotValidPeer(ctx context.Context, accountID string, peer *nbpeer.Peer, peersGroup []string, extraSettings *types.ExtraSettings) (bool, bool, error)
	GetValidatedPeers(ctx context.Context, accountID string, groups []*types.Group, peers []*nbpeer.Peer, extraSettings *types.ExtraSettings) (map[string]struct{}, map[string]string, error)
	PeerDeleted(ctx context.Context, accountID, peerID string, extraSettings *types.ExtraSettings) error
	SetPeerInvalidationListener(fn func(accountID string, peerIDs []string))
	Stop(ctx context.Context)
	ValidateFlowResponse(ctx context.Context, peerKey string, flowResponse *proto.PKCEAuthorizationFlow) *proto.PKCEAuthorizationFlow
}
