package server

import (
	"context"
	"slices"

	log "github.com/sirupsen/logrus"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/management/server/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

const (
	dnsForwarderPort = nbdns.ForwarderServerPort
)

// GetDNSSettings validates a user role and returns the DNS settings for the provided account ID
func (am *DefaultAccountManager) GetDNSSettings(ctx context.Context, accountID string, userID string) (*types.DNSSettings, error) {
	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Dns, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !allowed {
		return nil, status.NewPermissionDeniedError()
	}

	return am.Store.GetAccountDNSSettings(ctx, store.LockingStrengthNone, accountID)
}

// SaveDNSSettings validates a user role and updates the account's DNS settings
func (am *DefaultAccountManager) SaveDNSSettings(ctx context.Context, accountID string, userID string, dnsSettingsToSave *types.DNSSettings) error {
	if dnsSettingsToSave == nil {
		return status.Errorf(status.InvalidArgument, "the dns settings provided are nil")
	}

	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Dns, operations.Update)
	if err != nil {
		return status.NewPermissionValidationError(err)
	}
	if !allowed {
		return status.NewPermissionDeniedError()
	}

	var updateAccountPeers bool
	var eventsToStore []func()

	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		if err = validateDNSSettings(ctx, transaction, accountID, dnsSettingsToSave); err != nil {
			return err
		}

		oldSettings, err := transaction.GetAccountDNSSettings(ctx, store.LockingStrengthUpdate, accountID)
		if err != nil {
			return err
		}

		addedGroups := util.Difference(dnsSettingsToSave.DisabledManagementGroups, oldSettings.DisabledManagementGroups)
		removedGroups := util.Difference(oldSettings.DisabledManagementGroups, dnsSettingsToSave.DisabledManagementGroups)

		updateAccountPeers, err = areDNSSettingChangesAffectPeers(ctx, transaction, accountID, addedGroups, removedGroups)
		if err != nil {
			return err
		}

		events := am.prepareDNSSettingsEvents(ctx, transaction, accountID, userID, addedGroups, removedGroups)
		eventsToStore = append(eventsToStore, events...)

		if err = transaction.SaveDNSSettings(ctx, accountID, dnsSettingsToSave); err != nil {
			return err
		}

		return transaction.IncrementNetworkSerial(ctx, accountID)
	})
	if err != nil {
		return err
	}

	for _, storeEvent := range eventsToStore {
		storeEvent()
	}

	if updateAccountPeers {
		am.UpdateAccountPeers(ctx, accountID)
	}

	return nil
}

// prepareDNSSettingsEvents prepares a list of event functions to be stored.
func (am *DefaultAccountManager) prepareDNSSettingsEvents(ctx context.Context, transaction store.Store, accountID, userID string, addedGroups, removedGroups []string) []func() {
	var eventsToStore []func()

	modifiedGroups := slices.Concat(addedGroups, removedGroups)
	groups, err := transaction.GetGroupsByIDs(ctx, store.LockingStrengthNone, accountID, modifiedGroups)
	if err != nil {
		log.WithContext(ctx).Debugf("failed to get groups for dns settings events: %v", err)
		return nil
	}

	for _, groupID := range addedGroups {
		group, ok := groups[groupID]
		if !ok {
			log.WithContext(ctx).Debugf("skipped adding group: %s GroupAddedToDisabledManagementGroups activity", groupID)
			continue
		}

		eventsToStore = append(eventsToStore, func() {
			meta := map[string]any{"group": group.Name, "group_id": group.ID}
			am.StoreEvent(ctx, userID, accountID, accountID, activity.GroupAddedToDisabledManagementGroups, meta)
		})

	}

	for _, groupID := range removedGroups {
		group, ok := groups[groupID]
		if !ok {
			log.WithContext(ctx).Debugf("skipped adding group: %s GroupRemovedFromDisabledManagementGroups activity", groupID)
			continue
		}

		eventsToStore = append(eventsToStore, func() {
			meta := map[string]any{"group": group.Name, "group_id": group.ID}
			am.StoreEvent(ctx, userID, accountID, accountID, activity.GroupRemovedFromDisabledManagementGroups, meta)
		})
	}

	return eventsToStore
}

// areDNSSettingChangesAffectPeers checks if the DNS settings changes affect any peers.
func areDNSSettingChangesAffectPeers(ctx context.Context, transaction store.Store, accountID string, addedGroups, removedGroups []string) (bool, error) {
	hasPeers, err := anyGroupHasPeersOrResources(ctx, transaction, accountID, addedGroups)
	if err != nil {
		return false, err
	}

	if hasPeers {
		return true, nil
	}

	return anyGroupHasPeersOrResources(ctx, transaction, accountID, removedGroups)
}

// validateDNSSettings validates the DNS settings.
func validateDNSSettings(ctx context.Context, transaction store.Store, accountID string, settings *types.DNSSettings) error {
	if len(settings.DisabledManagementGroups) == 0 {
		return nil
	}

	groups, err := transaction.GetGroupsByIDs(ctx, store.LockingStrengthNone, accountID, settings.DisabledManagementGroups)
	if err != nil {
		return err
	}

	return validateGroups(settings.DisabledManagementGroups, groups)
}
