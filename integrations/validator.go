package integrations

import (
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/group"
	"github.com/netbirdio/netbird/management/server/peer"

	"github.com/netbirdio/netbird/integrations/validator"
)

type IntegratedValidatorImpl struct {
}

func NewIntegratedValidator(activity.Store) (validator.IntegratedValidator, error) {
	return &IntegratedValidatorImpl{}, nil
}

func (v *IntegratedValidatorImpl) ValidateExtraSettings(*account.ExtraSettings, *account.ExtraSettings, map[string]*peer.Peer, string, string) error {
	return nil
}

func (v *IntegratedValidatorImpl) ValidatePeer(update *peer.Peer, _ *peer.Peer, _ string, _ string, _ string, _ []string, _ *account.ExtraSettings) (*peer.Peer, error) {
	return update, nil
}

func (v *IntegratedValidatorImpl) PreparePeer(_ string, peer *peer.Peer, _ []string, _ *account.ExtraSettings) *peer.Peer {
	return peer.Copy()
}

func (v *IntegratedValidatorImpl) IsNotValidPeer(_ string, _ *peer.Peer, _ []string, _ *account.ExtraSettings) (bool, bool) {
	return false, false
}

func (v *IntegratedValidatorImpl) GetValidatedPeers(_ string, _ map[string]*group.Group, peers map[string]*peer.Peer, _ *account.ExtraSettings) (map[string]struct{}, error) {
	validatedPeers := make(map[string]struct{})
	for p := range peers {
		validatedPeers[p] = struct{}{}
	}
	return validatedPeers, nil
}

func (v *IntegratedValidatorImpl) PeerDeleted(_, _ string) error {
	return nil
}

func (v *IntegratedValidatorImpl) SetPeerInvalidationListener(_ func(accountID string)) {

}

func (v *IntegratedValidatorImpl) Stop() {
}
