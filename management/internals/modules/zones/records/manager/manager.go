package manager

import (
	"context"
	"fmt"

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

	if err = m.validateRecordConflicts(ctx, accountID, zoneID, record.Name, record.Type, record.Content, ""); err != nil {
		return nil, err
	}

	record = records.NewRecord(accountID, zoneID, record.Name, record.Type, record.Content, record.TTL)
	err = m.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
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

	m.accountManager.StoreEvent(ctx, userID, record.ID, accountID, activity.DNSRecordCreated, record.EventMeta())

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

	record, err := m.store.GetDNSRecordByID(ctx, store.LockingStrengthUpdate, accountID, zoneID, updatedRecord.ID)
	if err != nil {
		return nil, err
	}

	if record.Name != updatedRecord.Name || record.Type != updatedRecord.Type || record.Content != updatedRecord.Content {
		if err = m.validateRecordConflicts(ctx, accountID, zoneID, updatedRecord.Name, updatedRecord.Type, updatedRecord.Content, record.ID); err != nil {
			return nil, err
		}
	}

	record.Name = updatedRecord.Name
	record.Type = updatedRecord.Type
	record.Content = updatedRecord.Content
	record.TTL = updatedRecord.TTL

	err = m.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
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

	m.accountManager.StoreEvent(ctx, userID, record.ID, accountID, activity.DNSRecordUpdated, record.EventMeta())

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

	record, err := m.store.GetDNSRecordByID(ctx, store.LockingStrengthUpdate, accountID, zoneID, recordID)
	if err != nil {
		return err
	}

	var eventsToStore []func()
	err = m.store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		err = transaction.DeleteDNSRecord(ctx, accountID, recordID)
		if err != nil {
			return fmt.Errorf("failed to delete dns record: %w", err)
		}

		eventsToStore = append(eventsToStore, func() {
			m.accountManager.StoreEvent(ctx, userID, recordID, accountID, activity.DNSRecordDeleted, record.EventMeta())
		})

		err = transaction.IncrementNetworkSerial(ctx, accountID)
		if err != nil {
			return fmt.Errorf("failed to increment network serial: %w", err)
		}

		return nil
	})
	if err != nil {
		return err
	}

	for _, event := range eventsToStore {
		event()
	}

	go m.accountManager.UpdateAccountPeers(ctx, accountID)

	return nil
}

// validateRecordConflicts checks for duplicate records and CNAME conflicts.
func (m *managerImpl) validateRecordConflicts(ctx context.Context, accountID, zoneID, name string, recordType records.RecordType, content, excludeRecordID string) error {
	existingRecords, err := m.store.GetZoneDNSRecordsByName(ctx, store.LockingStrengthNone, accountID, zoneID, name)
	if err != nil {
		return fmt.Errorf("failed to check existing records: %w", err)
	}

	for _, existing := range existingRecords {
		if existing.ID == excludeRecordID {
			continue
		}

		if existing.Type == recordType && existing.Content == content {
			return status.Errorf(status.AlreadyExists, "identical record already exists")
		}

		if recordType == records.RecordTypeCNAME || existing.Type == records.RecordTypeCNAME {
			return status.Errorf(status.InvalidArgument,
				"An A, AAAA, or CNAME record with name %s already exists", name)
		}
	}

	return nil
}
