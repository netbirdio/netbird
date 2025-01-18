package server

import (
	"context"
	"errors"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/account"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

// UpdateIntegratedValidatorGroups updates the integrated validator groups for a specified account.
// It retrieves the account associated with the provided userID, then updates the integrated validator groups
// with the provided list of group ids. The updated account is then saved.
//
// Parameters:
//   - accountID: The ID of the account for which integrated validator groups are to be updated.
//   - userID: The ID of the user whose account is being updated.
//   - groups: A slice of strings representing the ids of integrated validator groups to be updated.
//
// Returns:
//   - error: An error if any occurred during the process, otherwise returns nil
func (am *DefaultAccountManager) UpdateIntegratedValidatorGroups(ctx context.Context, accountID string, userID string, groups []string) error {
	ok, err := am.GroupValidation(ctx, accountID, groups)
	if err != nil {
		log.WithContext(ctx).Debugf("error validating groups: %s", err.Error())
		return err
	}

	if !ok {
		log.WithContext(ctx).Debugf("invalid groups")
		return errors.New("invalid groups")
	}

	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()

	a, err := am.Store.GetAccountByUser(ctx, userID)
	if err != nil {
		return err
	}

	var extra *account.ExtraSettings

	if a.Settings.Extra != nil {
		extra = a.Settings.Extra
	} else {
		extra = &account.ExtraSettings{}
		a.Settings.Extra = extra
	}
	extra.IntegratedValidatorGroups = groups
	return am.Store.SaveAccount(ctx, a)
}

func (am *DefaultAccountManager) GroupValidation(ctx context.Context, accountID string, groupIDs []string) (bool, error) {
	if len(groupIDs) == 0 {
		return true, nil
	}

	err := am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		for _, groupID := range groupIDs {
			_, err := transaction.GetGroupByID(context.Background(), store.LockingStrengthShare, accountID, groupID)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return false, err
	}

	return true, nil
}

func (am *DefaultAccountManager) GetValidatedPeers(ctx context.Context, accountID string) (map[string]struct{}, error) {
	var err error
	var groups []*types.Group
	var peers []*nbpeer.Peer
	var settings *types.Settings

	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		groups, err = transaction.GetAccountGroups(ctx, store.LockingStrengthShare, accountID)
		if err != nil {
			return err
		}

		peers, err = transaction.GetAccountPeers(ctx, store.LockingStrengthShare, accountID)
		return err
	})
	if err != nil {
		return nil, err
	}

	settings, err = am.Store.GetAccountSettings(ctx, store.LockingStrengthShare, accountID)
	if err != nil {
		return nil, err
	}

	return am.integratedPeerValidator.GetValidatedPeers(accountID, groups, peers, settings.Extra)
}

type MocIntegratedValidator struct {
	ValidatePeerFunc func(_ context.Context, update *nbpeer.Peer, peer *nbpeer.Peer, userID string, accountID string, dnsDomain string, peersGroup []string, extraSettings *account.ExtraSettings) (*nbpeer.Peer, bool, error)
}

func (a MocIntegratedValidator) ValidateExtraSettings(_ context.Context, newExtraSettings *account.ExtraSettings, oldExtraSettings *account.ExtraSettings, peers map[string]*nbpeer.Peer, userID string, accountID string) error {
	return nil
}

func (a MocIntegratedValidator) ValidatePeer(_ context.Context, update *nbpeer.Peer, peer *nbpeer.Peer, userID string, accountID string, dnsDomain string, peersGroup []string, extraSettings *account.ExtraSettings) (*nbpeer.Peer, bool, error) {
	if a.ValidatePeerFunc != nil {
		return a.ValidatePeerFunc(context.Background(), update, peer, userID, accountID, dnsDomain, peersGroup, extraSettings)
	}
	return update, false, nil
}

func (a MocIntegratedValidator) GetValidatedPeers(accountID string, groups []*types.Group, peers []*nbpeer.Peer, extraSettings *account.ExtraSettings) (map[string]struct{}, error) {
	validatedPeers := make(map[string]struct{})
	for _, peer := range peers {
		validatedPeers[peer.ID] = struct{}{}
	}
	return validatedPeers, nil
}

func (MocIntegratedValidator) PreparePeer(_ context.Context, accountID string, peer *nbpeer.Peer, peersGroup []string, extraSettings *account.ExtraSettings) *nbpeer.Peer {
	return peer
}

func (MocIntegratedValidator) IsNotValidPeer(_ context.Context, accountID string, peer *nbpeer.Peer, peersGroup []string, extraSettings *account.ExtraSettings) (bool, bool, error) {
	return false, false, nil
}

func (MocIntegratedValidator) PeerDeleted(_ context.Context, _, _ string) error {
	return nil
}

func (MocIntegratedValidator) SetPeerInvalidationListener(func(accountID string)) {
	// just a dummy
}

func (MocIntegratedValidator) Stop(_ context.Context) {
	// just a dummy
}
