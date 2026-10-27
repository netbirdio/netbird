package manager

import (
	"context"
	"fmt"
	"slices"

	"github.com/netbirdio/netbird/management/internals/modules/zones"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/affectedpeers"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/status"
)

type managerImpl struct {
	store              store.Store
	accountManager     account.Manager
	permissionsManager permissions.Manager
	dnsDomain          string
}

func NewManager(store store.Store, accountManager account.Manager, permissionsManager permissions.Manager, dnsDomain string) zones.Manager {
	return &managerImpl{
		store:              store,
		accountManager:     accountManager,
		permissionsManager: permissionsManager,
		dnsDomain:          dnsDomain,
	}
}

func (m *managerImpl) GetAllZones(ctx context.Context, accountID, userID string) ([]*zones.Zone, error) {
	ok, ctx, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Dns, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	return m.store.GetAccountZones(ctx, store.LockingStrengthNone, accountID)
}

func (m *managerImpl) GetZone(ctx context.Context, accountID, userID, zoneID string) (*zones.Zone, error) {
	ok, ctx, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Dns, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	return m.store.GetZoneByID(ctx, store.LockingStrengthNone, accountID, zoneID)
}

func (m *managerImpl) CreateZone(ctx context.Context, accountID, userID string, zone *zones.Zone) (*zones.Zone, error) {
	ok, ctx, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Dns, operations.Create)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	if err = m.validateZoneDomainConflict(ctx, accountID, zone.Domain); err != nil {
		return nil, err
	}

	zone = zones.NewZone(accountID, zone.Name, zone.Domain, zone.Enabled, zone.EnableSearchDomain, zone.DistributionGroups)
	var snap *affectedpeers.Snapshot
	change := affectedpeers.Change{DistributionGroupIDs: zone.DistributionGroups}

	err = m.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		existingZone, err := transaction.GetZoneByDomain(ctx, accountID, zone.Domain)
		if err != nil {
			if sErr, ok := status.FromError(err); !ok || sErr.Type() != status.NotFound {
				return fmt.Errorf("failed to check existing zone: %w", err)
			}
		}
		if existingZone != nil {
			return status.Errorf(status.AlreadyExists, "zone with domain %s already exists", zone.Domain)
		}

		for _, groupID := range zone.DistributionGroups {
			_, err = transaction.GetGroupByID(ctx, store.LockingStrengthNone, accountID, groupID)
			if err != nil {
				return status.Errorf(status.InvalidArgument, "%s", err.Error())
			}
		}

		if err = transaction.CreateZone(ctx, zone); err != nil {
			return fmt.Errorf("create zone: %w", err)
		}

		if snap, err = affectedpeers.Load(ctx, transaction, accountID, change); err != nil {
			return fmt.Errorf("load affected peers: %w", err)
		}

		if err = transaction.IncrementNetworkSerial(ctx, accountID); err != nil {
			return fmt.Errorf("increment network serial: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	m.accountManager.StoreEvent(ctx, userID, zone.ID, accountID, activity.DNSZoneCreated, zone.EventMeta())

	m.accountManager.ExpandAndUpdateAffected(ctx, accountID, snap, change)

	return zone, nil
}

func (m *managerImpl) UpdateZone(ctx context.Context, accountID, userID string, updatedZone *zones.Zone) (*zones.Zone, error) {
	ok, ctx, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Dns, operations.Update)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	var zone *zones.Zone
	var snap *affectedpeers.Snapshot
	var change affectedpeers.Change

	err = m.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		zone, err = transaction.GetZoneByID(ctx, store.LockingStrengthUpdate, accountID, updatedZone.ID)
		if err != nil {
			return fmt.Errorf("get zone: %w", err)
		}

		if zone.Domain != updatedZone.Domain {
			return status.Errorf(status.InvalidArgument, "zone domain cannot be updated")
		}

		oldGroups := zone.DistributionGroups
		zone.Name = updatedZone.Name
		zone.Enabled = updatedZone.Enabled
		zone.EnableSearchDomain = updatedZone.EnableSearchDomain
		zone.DistributionGroups = updatedZone.DistributionGroups

		for _, groupID := range zone.DistributionGroups {
			_, err = transaction.GetGroupByID(ctx, store.LockingStrengthNone, accountID, groupID)
			if err != nil {
				return status.Errorf(status.InvalidArgument, "%s", err.Error())
			}
		}

		if err = transaction.UpdateZone(ctx, zone); err != nil {
			return fmt.Errorf("update zone: %w", err)
		}

		change = affectedpeers.Change{DistributionGroupIDs: slices.Concat(zone.DistributionGroups, oldGroups)}
		if snap, err = affectedpeers.Load(ctx, transaction, accountID, change); err != nil {
			return fmt.Errorf("load affected peers: %w", err)
		}

		if err = transaction.IncrementNetworkSerial(ctx, accountID); err != nil {
			return fmt.Errorf("increment network serial: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	m.accountManager.StoreEvent(ctx, userID, zone.ID, accountID, activity.DNSZoneUpdated, zone.EventMeta())

	m.accountManager.ExpandAndUpdateAffected(ctx, accountID, snap, change)

	return zone, nil
}

func (m *managerImpl) DeleteZone(ctx context.Context, accountID, userID, zoneID string) error {
	ok, ctx, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Dns, operations.Delete)
	if err != nil {
		return status.NewPermissionValidationError(err)
	}
	if !ok {
		return status.NewPermissionDeniedError()
	}

	var zone *zones.Zone
	var snap *affectedpeers.Snapshot
	var change affectedpeers.Change
	var eventsToStore []func()

	err = m.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		zone, err = transaction.GetZoneByID(ctx, store.LockingStrengthUpdate, accountID, zoneID)
		if err != nil {
			return fmt.Errorf("get zone: %w", err)
		}

		// Load before delete: the post-delete state no longer references the groups.
		change = affectedpeers.Change{DistributionGroupIDs: zone.DistributionGroups}
		if snap, err = affectedpeers.Load(ctx, transaction, accountID, change); err != nil {
			return fmt.Errorf("load affected peers: %w", err)
		}

		records, err := transaction.GetZoneDNSRecords(ctx, store.LockingStrengthNone, accountID, zoneID)
		if err != nil {
			return fmt.Errorf("failed to get records: %w", err)
		}

		err = transaction.DeleteZoneDNSRecords(ctx, accountID, zoneID)
		if err != nil {
			return fmt.Errorf("failed to delete zone dns records: %w", err)
		}

		err = transaction.DeleteZone(ctx, accountID, zoneID)
		if err != nil {
			return fmt.Errorf("failed to delete zone: %w", err)
		}

		err = transaction.IncrementNetworkSerial(ctx, accountID)
		if err != nil {
			return fmt.Errorf("failed to increment network serial: %w", err)
		}

		for _, record := range records {
			eventsToStore = append(eventsToStore, func() {
				meta := record.EventMeta(zone.ID, zone.Name)
				m.accountManager.StoreEvent(ctx, userID, record.ID, accountID, activity.DNSRecordDeleted, meta)
			})
		}

		eventsToStore = append(eventsToStore, func() {
			m.accountManager.StoreEvent(ctx, userID, zoneID, accountID, activity.DNSZoneDeleted, zone.EventMeta())
		})

		return nil
	})
	if err != nil {
		return err
	}

	for _, event := range eventsToStore {
		event()
	}

	m.accountManager.ExpandAndUpdateAffected(ctx, accountID, snap, change)

	return nil
}

func (m *managerImpl) validateZoneDomainConflict(ctx context.Context, accountID, domain string) error {
	if m.dnsDomain != "" && m.dnsDomain == domain {
		return status.Errorf(status.InvalidArgument, "zone domain %s conflicts with peer DNS domain", domain)
	}

	settings, err := m.store.GetAccountSettings(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return err
	}

	if settings.DNSDomain != "" && settings.DNSDomain == domain {
		return status.Errorf(status.InvalidArgument, "zone domain %s conflicts with peer DNS domain", domain)
	}

	return nil
}
