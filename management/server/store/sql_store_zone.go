package store

import (
	"context"
	"errors"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/netbirdio/netbird/management/internals/modules/zones"
	"github.com/netbirdio/netbird/shared/management/status"
)

func (s *SqlStore) CreateZone(ctx context.Context, zone *zones.Zone) error {
	result := s.db.Create(zone)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to create zone to store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to create zone to store")
	}

	return nil
}

func (s *SqlStore) UpdateZone(ctx context.Context, zone *zones.Zone) error {
	result := s.db.Select("*").Save(zone)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to update zone to store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to update zone to store")
	}

	return nil
}

func (s *SqlStore) DeleteZone(ctx context.Context, accountID, zoneID string) error {
	result := s.db.Delete(&zones.Zone{}, accountAndIDQueryCondition, accountID, zoneID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to delete zone from store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to delete zone from store")
	}

	if result.RowsAffected == 0 {
		return status.NewZoneNotFoundError(zoneID)
	}

	return nil
}

func (s *SqlStore) GetZoneByID(ctx context.Context, lockStrength LockingStrength, accountID, zoneID string) (*zones.Zone, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var zone *zones.Zone
	result := tx.Preload("Records").Take(&zone, accountAndIDQueryCondition, accountID, zoneID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.NewZoneNotFoundError(zoneID)
		}

		log.WithContext(ctx).Errorf("failed to get zone from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get zone from store")
	}

	return zone, nil
}

func (s *SqlStore) GetZoneByDomain(ctx context.Context, accountID, domain string) (*zones.Zone, error) {
	var zone *zones.Zone
	result := s.db.Where("account_id = ? AND domain = ?", accountID, domain).First(&zone)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.NewZoneNotFoundError(domain)
		}

		log.WithContext(ctx).Errorf("failed to get zone by domain from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get zone by domain from store")
	}

	return zone, nil
}

func (s *SqlStore) GetAccountZones(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*zones.Zone, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var zones []*zones.Zone
	result := tx.Preload("Records").Find(&zones, accountIDCondition, accountID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get zones from the store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get zones from store")
	}

	return zones, nil
}
