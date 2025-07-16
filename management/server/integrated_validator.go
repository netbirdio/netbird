package server

import (
	"context"
	"errors"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/integrations/integrated_validator"
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

	return am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		a, err := transaction.GetAccountByUser(ctx, userID)
		if err != nil {
			return err
		}

		var extra *types.ExtraSettings

		if a.Settings.Extra != nil {
			extra = a.Settings.Extra
		} else {
			extra = &types.ExtraSettings{}
			a.Settings.Extra = extra
		}
		extra.IntegratedValidatorGroups = groups
		return transaction.SaveAccount(ctx, a)
	})
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

	groups, err = am.Store.GetAccountGroups(ctx, store.LockingStrengthShare, accountID)
	if err != nil {
		return nil, err
	}

	peers, err = am.Store.GetAccountPeers(ctx, store.LockingStrengthShare, accountID, "", "")
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
	integrated_validator.IntegratedValidatorMock
	ValidatePeerFunc func(_ context.Context, update *nbpeer.Peer, peer *nbpeer.Peer, userID string, accountID string, dnsDomain string, peersGroup []string, extraSettings *types.ExtraSettings) (*nbpeer.Peer, bool, error)
}

func (a MocIntegratedValidator) ValidatePeer(_ context.Context, update *nbpeer.Peer, peer *nbpeer.Peer, userID string, accountID string, dnsDomain string, peersGroup []string, extraSettings *types.ExtraSettings) (*nbpeer.Peer, bool, error) {
	if a.ValidatePeerFunc != nil {
		return a.ValidatePeerFunc(context.Background(), update, peer, userID, accountID, dnsDomain, peersGroup, extraSettings)
	}
	return update, false, nil
}
