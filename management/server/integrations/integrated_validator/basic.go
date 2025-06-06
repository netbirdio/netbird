package integrated_validator

import (
	"context"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
)

// BasicValidator provides minimal peer approval validation based on account settings.
type BasicValidator struct{}

// NewBasicValidator creates a new BasicValidator instance.
func NewBasicValidator() *BasicValidator {
	return &BasicValidator{}
}

func (v *BasicValidator) ValidateExtraSettings(ctx context.Context, newExtraSettings *types.ExtraSettings, oldExtraSettings *types.ExtraSettings, peers map[string]*nbpeer.Peer, userID string, accountID string) error {
	return nil
}

func (v *BasicValidator) ValidatePeer(ctx context.Context, update *nbpeer.Peer, peer *nbpeer.Peer, userID string, accountID string, dnsDomain string, peersGroup []string, extraSettings *types.ExtraSettings) (*nbpeer.Peer, bool, error) {
	return update, false, nil
}

func (v *BasicValidator) PreparePeer(ctx context.Context, accountID string, peer *nbpeer.Peer, peersGroup []string, extraSettings *types.ExtraSettings) *nbpeer.Peer {
	if extraSettings != nil && extraSettings.PeerApprovalEnabled {
		if peer.Status == nil {
			peer.Status = &nbpeer.PeerStatus{}
		}
		peer.Status.RequiresApproval = true
	}
	return peer
}

func (v *BasicValidator) IsNotValidPeer(ctx context.Context, accountID string, peer *nbpeer.Peer, peersGroup []string, extraSettings *types.ExtraSettings) (bool, bool, error) {
	if extraSettings != nil && extraSettings.PeerApprovalEnabled {
		if peer.Status != nil && peer.Status.RequiresApproval {
			return true, false, nil
		}
	}
	return false, false, nil
}

func (v *BasicValidator) GetValidatedPeers(accountID string, groups []*types.Group, peers []*nbpeer.Peer, extraSettings *types.ExtraSettings) (map[string]struct{}, error) {
	validated := make(map[string]struct{})
	for _, p := range peers {
		if extraSettings != nil && extraSettings.PeerApprovalEnabled {
			if p.Status != nil && p.Status.RequiresApproval {
				continue
			}
		}
		validated[p.ID] = struct{}{}
	}
	return validated, nil
}

func (v *BasicValidator) PeerDeleted(ctx context.Context, _, _ string) error {
	return nil
}

func (v *BasicValidator) SetPeerInvalidationListener(func(accountID string)) {}

func (v *BasicValidator) Stop(ctx context.Context) {}
