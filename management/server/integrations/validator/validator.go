package validator

import (
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/group"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

type IntegratedValidator interface {
	ValidateExtraSettings(newExtraSettings *account.ExtraSettings, oldExtraSettings *account.ExtraSettings, peers map[string]*nbpeer.Peer, userID string, accountID string) error
	ValidatePeer(update *nbpeer.Peer, peer *nbpeer.Peer, userID string, accountID string, dnsDomain string, peersGroup []string, extraSettings *account.ExtraSettings) (*nbpeer.Peer, error)
	PreparePeer(accountID string, peer *nbpeer.Peer, peersGroup []string, extraSettings *account.ExtraSettings) *nbpeer.Peer
	IsNotValidPeer(accountID string, peer *nbpeer.Peer, peersGroup []string, extraSettings *account.ExtraSettings) (bool, bool)
	GetValidatedPeers(accountID string, groups map[string]*group.Group, peers map[string]*nbpeer.Peer, extraSettings *account.ExtraSettings) (map[string]struct{}, error)
	PeerDeleted(accountID, peerID string) error
	SetPeerInvalidationListener(fn func(accountID string))
	Stop()
}

type IntegratedValidatorImpl struct {
}

func NewIntegratedValidator(activity.Store) (IntegratedValidator, error) {
	return &IntegratedValidatorImpl{}, nil
}

func (v *IntegratedValidatorImpl) ValidateExtraSettings(*account.ExtraSettings, *account.ExtraSettings, map[string]*nbpeer.Peer, string, string) error {
	return nil
}

func (v *IntegratedValidatorImpl) ValidatePeer(update *nbpeer.Peer, _ *nbpeer.Peer, _ string, _ string, _ string, _ []string, _ *account.ExtraSettings) (*nbpeer.Peer, error) {
	return update, nil
}

func (v *IntegratedValidatorImpl) PreparePeer(_ string, peer *nbpeer.Peer, _ []string, _ *account.ExtraSettings) *nbpeer.Peer {
	return peer.Copy()
}

func (v *IntegratedValidatorImpl) IsNotValidPeer(_ string, _ *nbpeer.Peer, _ []string, _ *account.ExtraSettings) (bool, bool) {
	return false, false
}

func (v *IntegratedValidatorImpl) GetValidatedPeers(_ string, _ map[string]*group.Group, peers map[string]*nbpeer.Peer, _ *account.ExtraSettings) (map[string]struct{}, error) {
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
