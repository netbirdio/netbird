// SPDX-License-Identifier: BSD-3-Clause

package integrations

import (
	"context"

	cachestore "github.com/eko/gocache/lib/v4/store"
	"github.com/netbirdio/netbird/management/internals/modules/peers"
	"github.com/netbirdio/netbird/management/server/activity"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/settings"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// IntegratedValidatorImpl mirrors the original module: without external
// posture validators every peer is considered valid.
type IntegratedValidatorImpl struct {
}

// NewIntegratedValidator returns the pass-through integrated validator.
func NewIntegratedValidator(_ context.Context, _ peers.Manager, _ settings.Manager, _ activity.Store, _ cachestore.StoreInterface) (*IntegratedValidatorImpl, error) {
	return &IntegratedValidatorImpl{}, nil
}

// ValidateExtraSettings accepts every extra settings change.
func (v *IntegratedValidatorImpl) ValidateExtraSettings(context.Context, *types.ExtraSettings, *types.ExtraSettings, string, string) error {
	return nil
}

// ValidatePeer passes the peer update through unmodified.
func (v *IntegratedValidatorImpl) ValidatePeer(_ context.Context, update *nbpeer.Peer, _ *nbpeer.Peer, _ string, _ string, _ string, _ []string, _ *types.ExtraSettings) (*nbpeer.Peer, bool, error) {
	return update, false, nil
}

// PreparePeer returns a copy of the peer without applying posture side effects.
func (v *IntegratedValidatorImpl) PreparePeer(_ context.Context, _ string, peer *nbpeer.Peer, _ []string, _ *types.ExtraSettings, _ bool) *nbpeer.Peer {
	return peer.Copy()
}

// IsNotValidPeer reports no peer as invalid.
func (v *IntegratedValidatorImpl) IsNotValidPeer(_ context.Context, _ string, _ *nbpeer.Peer, _ []string, _ *types.ExtraSettings) (bool, bool, error) {
	return false, false, nil
}

// GetValidatedPeers marks every given peer as validated.
func (v *IntegratedValidatorImpl) GetValidatedPeers(_ context.Context, _ string, _ []*nmdata.Group, peers []*nmdata.Peer, _ *types.ExtraSettings) (map[string]struct{}, error) {
	validatedPeers := make(map[string]struct{})
	for _, p := range peers {
		validatedPeers[p.ID] = struct{}{}
	}
	return validatedPeers, nil
}

// GetInvalidPeers returns no invalid peers for the account.
func (v *IntegratedValidatorImpl) GetInvalidPeers(ctx context.Context, accountID string, extraSettings *types.ExtraSettings) (map[string]string, error) {
	return make(map[string]string), nil
}

// PeerDeleted ignores peer deletion notifications.
func (v *IntegratedValidatorImpl) PeerDeleted(ctx context.Context, _, _ string, extraSettings *types.ExtraSettings) error {
	return nil
}

// SetPeerInvalidationListener ignores the listener registration.
func (v *IntegratedValidatorImpl) SetPeerInvalidationListener(_ func(accountID string, peerIDs []string)) {
}

// Stop shuts the validator down; there is nothing to release.
func (v *IntegratedValidatorImpl) Stop(ctx context.Context) {
}

// ValidateFlowResponse passes PKCE authorization flow responses through.
func (v *IntegratedValidatorImpl) ValidateFlowResponse(ctx context.Context, peerKey string, flowResponse *proto.PKCEAuthorizationFlow) *proto.PKCEAuthorizationFlow {
	return flowResponse
}
