package server

import (
	"context"
	"slices"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/status"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/management/server/util"
)

const (
	// UpdateSetupKeyName indicates a setup key name update operation
	UpdateSetupKeyName SetupKeyUpdateOperationType = iota
	// UpdateSetupKeyRevoked indicates a setup key revoked filed update operation
	UpdateSetupKeyRevoked
	// UpdateSetupKeyAutoGroups indicates a setup key auto-assign groups update operation
	UpdateSetupKeyAutoGroups
	// UpdateSetupKeyExpiresAt indicates a setup key expiration time update operation
	UpdateSetupKeyExpiresAt
)

// SetupKeyUpdateOperationType operation type
type SetupKeyUpdateOperationType int

func (t SetupKeyUpdateOperationType) String() string {
	switch t {
	case UpdateSetupKeyName:
		return "UpdateSetupKeyName"
	case UpdateSetupKeyRevoked:
		return "UpdateSetupKeyRevoked"
	case UpdateSetupKeyAutoGroups:
		return "UpdateSetupKeyAutoGroups"
	case UpdateSetupKeyExpiresAt:
		return "UpdateSetupKeyExpiresAt"
	default:
		return "InvalidOperation"
	}
}

// SetupKeyUpdateOperation operation object with type and values to be applied
type SetupKeyUpdateOperation struct {
	Type   SetupKeyUpdateOperationType
	Values []string
}

// CreateSetupKey generates a new setup key with a given name, type, list of groups IDs to auto-assign to peers registered with this key,
// and adds it to the specified account. A list of autoGroups IDs can be empty.
func (am *DefaultAccountManager) CreateSetupKey(ctx context.Context, accountID string, keyName string, keyType types.SetupKeyType,
	expiresIn time.Duration, autoGroups []string, usageLimit int, userID string, ephemeral bool) (*types.SetupKey, error) {
	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()

	user, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthShare, userID)
	if err != nil {
		return nil, err
	}

	if user.AccountID != accountID {
		return nil, status.NewUserNotPartOfAccountError()
	}

	if user.IsRegularUser() {
		return nil, status.NewAdminPermissionError()
	}

	var setupKey *types.SetupKey
	var plainKey string
	var eventsToStore []func()

	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		if err = validateSetupKeyAutoGroups(ctx, transaction, accountID, autoGroups); err != nil {
			return status.Errorf(status.InvalidArgument, "invalid auto groups: %v", err)
		}

		setupKey, plainKey = types.GenerateSetupKey(keyName, keyType, expiresIn, autoGroups, usageLimit, ephemeral)
		setupKey.AccountID = accountID

		events := am.prepareSetupKeyEvents(ctx, transaction, accountID, userID, autoGroups, nil, setupKey)
		eventsToStore = append(eventsToStore, events...)

		return transaction.SaveSetupKey(ctx, store.LockingStrengthUpdate, setupKey)
	})
	if err != nil {
		return nil, err
	}

	am.StoreEvent(ctx, userID, setupKey.Id, accountID, activity.SetupKeyCreated, setupKey.EventMeta())
	for _, storeEvent := range eventsToStore {
		storeEvent()
	}

	// for the creation return the plain key to the caller
	setupKey.Key = plainKey

	return setupKey, nil
}

// SaveSetupKey saves the provided SetupKey to the database overriding the existing one.
// Due to the unique nature of a SetupKey certain properties must not be overwritten
// (e.g. the key itself, creation date, ID, etc).
// These properties are overwritten: AutoGroups, Revoked (only from false to true), and the UpdatedAt. The rest is copied from the existing key.
func (am *DefaultAccountManager) SaveSetupKey(ctx context.Context, accountID string, keyToSave *types.SetupKey, userID string) (*types.SetupKey, error) {
	if keyToSave == nil {
		return nil, status.Errorf(status.InvalidArgument, "provided setup key to update is nil")
	}

	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()

	user, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthShare, userID)
	if err != nil {
		return nil, err
	}

	if user.AccountID != accountID {
		return nil, status.NewUserNotPartOfAccountError()
	}

	if user.IsRegularUser() {
		return nil, status.NewAdminPermissionError()
	}

	var oldKey *types.SetupKey
	var newKey *types.SetupKey
	var eventsToStore []func()

	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		if err = validateSetupKeyAutoGroups(ctx, transaction, accountID, keyToSave.AutoGroups); err != nil {
			return status.Errorf(status.InvalidArgument, "invalid auto groups: %v", err)
		}

		oldKey, err = transaction.GetSetupKeyByID(ctx, store.LockingStrengthShare, accountID, keyToSave.Id)
		if err != nil {
			return err
		}

		if oldKey.Revoked && !keyToSave.Revoked {
			return status.Errorf(status.InvalidArgument, "can't un-revoke a revoked setup key")
		}

		// only auto groups, revoked status (from false to true) can be updated
		newKey = oldKey.Copy()
		newKey.AutoGroups = keyToSave.AutoGroups
		newKey.Revoked = keyToSave.Revoked
		newKey.UpdatedAt = time.Now().UTC()

		addedGroups := util.Difference(newKey.AutoGroups, oldKey.AutoGroups)
		removedGroups := util.Difference(oldKey.AutoGroups, newKey.AutoGroups)

		events := am.prepareSetupKeyEvents(ctx, transaction, accountID, userID, addedGroups, removedGroups, oldKey)
		eventsToStore = append(eventsToStore, events...)

		return transaction.SaveSetupKey(ctx, store.LockingStrengthUpdate, newKey)
	})
	if err != nil {
		return nil, err
	}

	if !oldKey.Revoked && newKey.Revoked {
		am.StoreEvent(ctx, userID, newKey.Id, accountID, activity.SetupKeyRevoked, newKey.EventMeta())
	}

	for _, storeEvent := range eventsToStore {
		storeEvent()
	}

	return newKey, nil
}

// ListSetupKeys returns a list of all setup keys of the account
func (am *DefaultAccountManager) ListSetupKeys(ctx context.Context, accountID, userID string) ([]*types.SetupKey, error) {
	user, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthShare, userID)
	if err != nil {
		return nil, err
	}

	if user.AccountID != accountID {
		return nil, status.NewUserNotPartOfAccountError()
	}

	if user.IsRegularUser() {
		return nil, status.NewAdminPermissionError()
	}

	return am.Store.GetAccountSetupKeys(ctx, store.LockingStrengthShare, accountID)
}

// GetSetupKey looks up a SetupKey by KeyID, returns NotFound error if not found.
func (am *DefaultAccountManager) GetSetupKey(ctx context.Context, accountID, userID, keyID string) (*types.SetupKey, error) {
	user, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthShare, userID)
	if err != nil {
		return nil, err
	}

	if user.AccountID != accountID {
		return nil, status.NewUserNotPartOfAccountError()
	}

	if user.IsRegularUser() {
		return nil, status.NewAdminPermissionError()
	}

	setupKey, err := am.Store.GetSetupKeyByID(ctx, store.LockingStrengthShare, accountID, keyID)
	if err != nil {
		return nil, err
	}

	// the UpdatedAt field was introduced later, so there might be that some keys have a Zero value (e.g, null in the store file)
	if setupKey.UpdatedAt.IsZero() {
		setupKey.UpdatedAt = setupKey.CreatedAt
	}

	return setupKey, nil
}

// DeleteSetupKey removes the setup key from the account
func (am *DefaultAccountManager) DeleteSetupKey(ctx context.Context, accountID, userID, keyID string) error {
	user, err := am.Store.GetUserByUserID(ctx, store.LockingStrengthShare, userID)
	if err != nil {
		return err
	}

	if user.AccountID != accountID {
		return status.NewUserNotPartOfAccountError()
	}

	if user.IsRegularUser() {
		return status.NewAdminPermissionError()
	}

	var deletedSetupKey *types.SetupKey

	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		deletedSetupKey, err = transaction.GetSetupKeyByID(ctx, store.LockingStrengthShare, accountID, keyID)
		if err != nil {
			return err
		}

		return transaction.DeleteSetupKey(ctx, store.LockingStrengthUpdate, accountID, keyID)
	})
	if err != nil {
		return err
	}

	am.StoreEvent(ctx, userID, keyID, accountID, activity.SetupKeyDeleted, deletedSetupKey.EventMeta())

	return nil
}

func validateSetupKeyAutoGroups(ctx context.Context, transaction store.Store, accountID string, autoGroupIDs []string) error {
	groups, err := transaction.GetGroupsByIDs(ctx, store.LockingStrengthShare, accountID, autoGroupIDs)
	if err != nil {
		return err
	}

	for _, groupID := range autoGroupIDs {
		group, ok := groups[groupID]
		if !ok {
			return status.Errorf(status.NotFound, "group not found: %s", groupID)
		}

		if group.IsGroupAll() {
			return status.Errorf(status.InvalidArgument, "can't add 'All' group to the setup key")
		}
	}

	return nil
}

// prepareSetupKeyEvents prepares a list of event functions to be stored.
func (am *DefaultAccountManager) prepareSetupKeyEvents(ctx context.Context, transaction store.Store, accountID, userID string, addedGroups, removedGroups []string, key *types.SetupKey) []func() {
	var eventsToStore []func()

	modifiedGroups := slices.Concat(addedGroups, removedGroups)
	groups, err := transaction.GetGroupsByIDs(ctx, store.LockingStrengthShare, accountID, modifiedGroups)
	if err != nil {
		log.WithContext(ctx).Debugf("failed to get groups for setup key events: %v", err)
		return nil
	}

	for _, g := range removedGroups {
		group, ok := groups[g]
		if !ok {
			log.WithContext(ctx).Debugf("skipped adding group: %s GroupRemovedFromSetupKey activity: group not found", g)
			continue
		}

		eventsToStore = append(eventsToStore, func() {
			meta := map[string]any{"group": group.Name, "group_id": group.ID, "setupkey": key.Name}
			am.StoreEvent(ctx, userID, key.Id, accountID, activity.GroupRemovedFromSetupKey, meta)
		})
	}

	for _, g := range addedGroups {
		group, ok := groups[g]
		if !ok {
			log.WithContext(ctx).Debugf("skipped adding group: %s GroupAddedToSetupKey activity: group not found", g)
			continue
		}

		eventsToStore = append(eventsToStore, func() {
			meta := map[string]any{"group": group.Name, "group_id": group.ID, "setupkey": key.Name}
			am.StoreEvent(ctx, userID, key.Id, accountID, activity.GroupAddedToSetupKey, meta)
		})
	}

	return eventsToStore
}
