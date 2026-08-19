package validator

import (
	"context"

	cachestore "github.com/eko/gocache/lib/v4/store"

	"github.com/netbirdio/netbird/management/internals/modules/peers"
	"github.com/netbirdio/netbird/management/server/activity"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/settings"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/proto"
)

type IntegratedValidatorImpl struct{}

func NewIntegratedValidator(_ context.Context, _ peers.Manager, _ settings.Manager, _ activity.Store, _ cachestore.StoreInterface) (*IntegratedValidatorImpl, error) {
	return &IntegratedValidatorImpl{}, nil
}

func (v *IntegratedValidatorImpl) ValidateExtraSettings(context.Context, *types.ExtraSettings, *types.ExtraSettings, string, string) error {
	return nil
}

func (v *IntegratedValidatorImpl) ValidatePeer(_ context.Context, update *nbpeer.Peer, _ *nbpeer.Peer, _ string, _ string, _ string, _ []string, _ *types.ExtraSettings) (*nbpeer.Peer, bool, error) {
	return update, false, nil
}

func (v *IntegratedValidatorImpl) PreparePeer(_ context.Context, _ string, peer *nbpeer.Peer, _ []string, _ *types.ExtraSettings, _ bool) *nbpeer.Peer {
	return peer.Copy()
}

func (v *IntegratedValidatorImpl) IsNotValidPeer(_ context.Context, _ string, _ *nbpeer.Peer, _ []string, _ *types.ExtraSettings) (bool, bool, error) {
	return false, false, nil
}

func (v *IntegratedValidatorImpl) GetValidatedPeers(_ context.Context, _ string, _ []*types.Group, peers []*nbpeer.Peer, _ *types.ExtraSettings) (map[string]struct{}, error) {
	validatedPeers := make(map[string]struct{})
	for _, p := range peers {
		validatedPeers[p.ID] = struct{}{}
	}
	return validatedPeers, nil
}

func (v *IntegratedValidatorImpl) GetInvalidPeers(_ context.Context, _ string, _ *types.ExtraSettings) (map[string]string, error) {
	return make(map[string]string), nil
}

func (v *IntegratedValidatorImpl) PeerDeleted(_ context.Context, _, _ string, _ *types.ExtraSettings) error {
	return nil
}

func (v *IntegratedValidatorImpl) SetPeerInvalidationListener(_ func(accountID string, peerIDs []string)) {
}

func (v *IntegratedValidatorImpl) Stop(_ context.Context) {
}

func (v *IntegratedValidatorImpl) ValidateFlowResponse(_ context.Context, _ string, flowResponse *proto.PKCEAuthorizationFlow) *proto.PKCEAuthorizationFlow {
	return flowResponse
}
