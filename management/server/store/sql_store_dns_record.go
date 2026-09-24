package store

import (
	"context"
	"errors"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/netbirdio/netbird/management/internals/modules/zones/records"
	"github.com/netbirdio/netbird/shared/management/status"
)

func (s *SqlStore) CreateDNSRecord(ctx context.Context, record *records.Record) error {
	result := s.db.Create(record)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to create dns record to store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to create dns record to store")
	}

	return nil
}

func (s *SqlStore) UpdateDNSRecord(ctx context.Context, record *records.Record) error {
	result := s.db.Select("*").Save(record)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to update dns record to store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to update dns record to store")
	}

	return nil
}

func (s *SqlStore) DeleteDNSRecord(ctx context.Context, accountID, zoneID, recordID string) error {
	result := s.db.Delete(&records.Record{}, "account_id = ? AND zone_id = ? AND id = ?", accountID, zoneID, recordID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to delete dns record from store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to delete dns record from store")
	}

	if result.RowsAffected == 0 {
		return status.NewDNSRecordNotFoundError(recordID)
	}

	return nil
}

func (s *SqlStore) GetDNSRecordByID(ctx context.Context, lockStrength LockingStrength, accountID, zoneID, recordID string) (*records.Record, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var record *records.Record
	result := tx.Where("account_id = ? AND zone_id = ? AND id = ?", accountID, zoneID, recordID).Take(&record)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.NewDNSRecordNotFoundError(recordID)
		}

		log.WithContext(ctx).Errorf("failed to get dns record from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get dns record from store")
	}

	return record, nil
}

func (s *SqlStore) GetZoneDNSRecords(ctx context.Context, lockStrength LockingStrength, accountID, zoneID string) ([]*records.Record, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var recordsList []*records.Record
	result := tx.Where("account_id = ? AND zone_id = ?", accountID, zoneID).Find(&recordsList)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get zone dns records from the store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get zone dns records from store")
	}

	return recordsList, nil
}

func (s *SqlStore) GetZoneDNSRecordsByName(ctx context.Context, lockStrength LockingStrength, accountID, zoneID, name string) ([]*records.Record, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var recordsList []*records.Record
	result := tx.Where("account_id = ? AND zone_id = ? AND name = ?", accountID, zoneID, name).Find(&recordsList)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get zone dns records by name from the store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get zone dns records by name from store")
	}

	return recordsList, nil
}

func (s *SqlStore) DeleteZoneDNSRecords(ctx context.Context, accountID, zoneID string) error {
	result := s.db.Delete(&records.Record{}, "account_id = ? AND zone_id = ?", accountID, zoneID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to delete zone dns records from store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to delete zone dns records from store")
	}

	return nil
}
