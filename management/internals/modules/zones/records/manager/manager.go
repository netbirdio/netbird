package manager

import (
	"context"
	"fmt"
	"strings"

	"github.com/netbirdio/netbird/management/internals/modules/zones"
	"github.com/netbirdio/netbird/management/internals/modules/zones/records"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/activity"
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
}

func NewManager(store store.Store, accountManager account.Manager, permissionsManager permissions.Manager) records.Manager {
	return &managerImpl{
		store:              store,
		accountManager:     accountManager,
		permissionsManager: permissionsManager,
	}
}

func (m *managerImpl) GetAllRecords(ctx context.Context, accountID, userID, zoneID string) ([]*records.Record, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Dns, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	return m.store.GetZoneDNSRecords(ctx, store.LockingStrengthNone, accountID, zoneID)
}

func (m *managerImpl) GetRecord(ctx context.Context, accountID, userID, zoneID, recordID string) (*records.Record, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Dns, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	return m.store.GetDNSRecordByID(ctx, store.LockingStrengthNone, accountID, zoneID, recordID)
}

func (m *managerImpl) CreateRecord(ctx context.Context, accountID, userID, zoneID string, record *records.Record) (*records.Record, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Dns, operations.Create)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	var zone *zones.Zone

	record = records.NewRecord(accountID, zoneID, record.Name, record.Type, record.Content, record.TTL)
	err = m.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		zone, err = transaction.GetZoneByID(ctx, store.LockingStrengthUpdate, accountID, zoneID)
		if err != nil {
			return fmt.Errorf("failed to get zone: %w", err)
		}

		err = validateRecordConflicts(ctx, transaction, zone, record)
		if err != nil {
			return err
		}

		if err = transaction.CreateDNSRecord(ctx, record); err != nil {
			return fmt.Errorf("failed to create dns record: %w", err)
		}

		err = transaction.IncrementNetworkSerial(ctx, accountID)
		if err != nil {
			return fmt.Errorf("failed to increment network serial: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	meta := record.EventMeta(zone.ID, zone.Name)
	m.accountManager.StoreEvent(ctx, userID, record.ID, accountID, activity.DNSRecordCreated, meta)

	go m.accountManager.UpdateAccountPeers(ctx, accountID)

	return record, nil
}

func (m *managerImpl) UpdateRecord(ctx context.Context, accountID, userID, zoneID string, updatedRecord *records.Record) (*records.Record, error) {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Dns, operations.Update)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !ok {
		return nil, status.NewPermissionDeniedError()
	}

	var zone *zones.Zone
	var record *records.Record

	err = m.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		zone, err = transaction.GetZoneByID(ctx, store.LockingStrengthUpdate, accountID, zoneID)
		if err != nil {
			return fmt.Errorf("failed to get zone: %w", err)
		}

		record, err = transaction.GetDNSRecordByID(ctx, store.LockingStrengthUpdate, accountID, zoneID, updatedRecord.ID)
		if err != nil {
			return fmt.Errorf("failed to get record: %w", err)
		}

		hasChanges := record.Name != updatedRecord.Name || record.Type != updatedRecord.Type || record.Content != updatedRecord.Content

		record.Name = updatedRecord.Name
		record.Type = updatedRecord.Type
		record.Content = updatedRecord.Content
		record.TTL = updatedRecord.TTL

		if hasChanges {
			if err = validateRecordConflicts(ctx, transaction, zone, record); err != nil {
				return err
			}
		}

		if err = transaction.UpdateDNSRecord(ctx, record); err != nil {
			return fmt.Errorf("failed to update dns record: %w", err)
		}

		err = transaction.IncrementNetworkSerial(ctx, accountID)
		if err != nil {
			return fmt.Errorf("failed to increment network serial: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	meta := record.EventMeta(zone.ID, zone.Name)
	m.accountManager.StoreEvent(ctx, userID, record.ID, accountID, activity.DNSRecordUpdated, meta)

	go m.accountManager.UpdateAccountPeers(ctx, accountID)

	return record, nil
}

func (m *managerImpl) DeleteRecord(ctx context.Context, accountID, userID, zoneID, recordID string) error {
	ok, err := m.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Dns, operations.Delete)
	if err != nil {
		return status.NewPermissionValidationError(err)
	}
	if !ok {
		return status.NewPermissionDeniedError()
	}

	var record *records.Record
	var zone *zones.Zone

	err = m.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		zone, err = transaction.GetZoneByID(ctx, store.LockingStrengthUpdate, accountID, zoneID)
		if err != nil {
			return fmt.Errorf("failed to get zone: %w", err)
		}

		record, err = transaction.GetDNSRecordByID(ctx, store.LockingStrengthUpdate, accountID, zoneID, recordID)
		if err != nil {
			return fmt.Errorf("failed to get record: %w", err)
		}

		err = transaction.DeleteDNSRecord(ctx, accountID, zoneID, recordID)
		if err != nil {
			return fmt.Errorf("failed to delete dns record: %w", err)
		}

		err = transaction.IncrementNetworkSerial(ctx, accountID)
		if err != nil {
			return fmt.Errorf("failed to increment network serial: %w", err)
		}

		return nil
	})
	if err != nil {
		return err
	}

	meta := record.EventMeta(zone.ID, zone.Name)
	m.accountManager.StoreEvent(ctx, userID, recordID, accountID, activity.DNSRecordDeleted, meta)

	go m.accountManager.UpdateAccountPeers(ctx, accountID)

	return nil
}

// validateRecordConflicts checks for duplicate records and CNAME conflicts
func validateRecordConflicts(ctx context.Context, transaction store.Store, zone *zones.Zone, record *records.Record) error {
	if record.Name != zone.Domain && !strings.HasSuffix(record.Name, "."+zone.Domain) {
		return status.Errorf(status.InvalidArgument, "record name does not belong to zone")
	}

	existingRecords, err := transaction.GetZoneDNSRecordsByName(ctx, store.LockingStrengthNone, zone.AccountID, zone.ID, record.Name)
	if err != nil {
		return fmt.Errorf("failed to check existing records: %w", err)
	}

	for _, existing := range existingRecords {
		if existing.ID == record.ID {
			continue
		}

		if existing.Type == record.Type && existing.Content == record.Content {
			return status.Errorf(status.AlreadyExists, "identical record already exists")
		}

		if record.Type == records.RecordTypeCNAME || existing.Type == records.RecordTypeCNAME {
			return status.Errorf(status.InvalidArgument,
				"An A, AAAA, or CNAME record with name %s already exists", record.Name)
		}
	}

	return nil
}
