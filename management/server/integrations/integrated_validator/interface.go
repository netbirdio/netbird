package integrated_validator

import (
	"context"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	"github.com/netbirdio/netbird/shared/management/proto"
)

//go:generate go tool mockgen -package integrated_validator -destination=integrated_validator_mock.go -source=./interface.go -build_flags=-mod=mod

// IntegratedValidator interface exists to avoid the circle dependencies
type IntegratedValidator interface {
	ValidateExtraSettings(ctx context.Context, newExtraSettings *types.ExtraSettings, oldExtraSettings *types.ExtraSettings, userID string, accountID string) error
	ValidatePeer(ctx context.Context, update *nbpeer.Peer, p *nbpeer.Peer, userID string, accountID string, dnsDomain string, peersGroup []string, extraSettings *types.ExtraSettings) (*nbpeer.Peer, bool, error)
	PreparePeer(ctx context.Context, accountID string, p *nbpeer.Peer, peersGroup []string, extraSettings *types.ExtraSettings, temporary bool) *nbpeer.Peer
	IsNotValidPeer(ctx context.Context, accountID string, peer *nbpeer.Peer, peersGroup []string, extraSettings *types.ExtraSettings) (bool, bool, error)
	GetValidatedPeers(ctx context.Context, accountID string, groups []*nmdata.Group, peers []*nmdata.Peer, extraSettings *types.ExtraSettings) (map[string]struct{}, error)
	GetInvalidPeers(ctx context.Context, accountID string, extraSettings *types.ExtraSettings) (map[string]string, error)
	PeerDeleted(ctx context.Context, accountID, peerID string, extraSettings *types.ExtraSettings) error
	SetPeerInvalidationListener(fn func(accountID string, peerIDs []string))
	Stop(ctx context.Context)
	ValidateFlowResponse(ctx context.Context, peerKey string, flowResponse *proto.PKCEAuthorizationFlow) *proto.PKCEAuthorizationFlow
}
