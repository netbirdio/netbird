package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

func (s *SqlStore) getNetworkResources(ctx context.Context, accountID string) ([]*resourceTypes.NetworkResource, error) {
	const query = `SELECT id, network_id, account_id, public_id, name, description, type, domain, prefix, enabled FROM network_resources WHERE account_id = $1`
	rows, err := s.pool.Query(ctx, query, accountID)
	if err != nil {
		return nil, err
	}
	resources, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (resourceTypes.NetworkResource, error) {
		var r resourceTypes.NetworkResource
		var prefix []byte
		var enabled sql.NullBool
		err := row.Scan(&r.ID, &r.NetworkID, &r.AccountID, &r.PublicID, &r.Name, &r.Description, &r.Type, &r.Domain, &prefix, &enabled)
		if err == nil {
			if enabled.Valid {
				r.Enabled = enabled.Bool
			}
			if prefix != nil {
				_ = json.Unmarshal(prefix, &r.Prefix)
			}
		}
		return r, err
	})
	if err != nil {
		return nil, err
	}
	result := make([]*resourceTypes.NetworkResource, len(resources))
	for i := range resources {
		result[i] = &resources[i]
	}
	return result, nil
}

func (s *SqlStore) GetNetworkResourcesByNetID(ctx context.Context, lockStrength LockingStrength, accountID, networkID string) ([]*resourceTypes.NetworkResource, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var netResources []*resourceTypes.NetworkResource
	result := tx.
		Find(&netResources, "account_id = ? AND network_id = ?", accountID, networkID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get network resources from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get network resources from store")
	}

	return netResources, nil
}

func (s *SqlStore) GetNetworkResourcesByAccountID(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*resourceTypes.NetworkResource, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var netResources []*resourceTypes.NetworkResource
	result := tx.
		Find(&netResources, accountIDCondition, accountID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get network resources from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get network resources from store")
	}

	return netResources, nil
}

func (s *SqlStore) GetNetworkResourceByID(ctx context.Context, lockStrength LockingStrength, accountID, resourceID string) (*resourceTypes.NetworkResource, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var netResources *resourceTypes.NetworkResource
	result := tx.
		Take(&netResources, accountAndIDQueryCondition, accountID, resourceID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.NewNetworkResourceNotFoundError(resourceID)
		}
		log.WithContext(ctx).Errorf("failed to get network resource from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get network resource from store")
	}

	return netResources, nil
}

// GetNetworkResourceByIDOrPublicID retrieves a network resource by either its ID or its
// PublicID. See GetPolicyByIDOrPublicID for why peer-reported references need both.
func (s *SqlStore) GetNetworkResourceByIDOrPublicID(ctx context.Context, lockStrength LockingStrength, accountID, resourceID string) (*resourceTypes.NetworkResource, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var netResources *resourceTypes.NetworkResource
	result := tx.
		Take(&netResources, accountAndAnyIDQueryCondition, accountID, resourceID, resourceID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.NewNetworkResourceNotFoundError(resourceID)
		}
		log.WithContext(ctx).Errorf("failed to get network resource from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get network resource from store")
	}

	return netResources, nil
}

func (s *SqlStore) GetNetworkResourceByName(ctx context.Context, lockStrength LockingStrength, accountID, resourceName string) (*resourceTypes.NetworkResource, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var netResources *resourceTypes.NetworkResource
	result := tx.
		Take(&netResources, "account_id = ? AND name = ?", accountID, resourceName)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.NewNetworkResourceNotFoundError(resourceName)
		}
		log.WithContext(ctx).Errorf("failed to get network resource from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get network resource from store")
	}

	return netResources, nil
}

func (s *SqlStore) SaveNetworkResource(ctx context.Context, resource *resourceTypes.NetworkResource) error {
	result := s.db.Save(resource)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to save network resource to store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to save network resource to store")
	}

	return nil
}

func (s *SqlStore) DeleteNetworkResource(ctx context.Context, accountID, resourceID string) error {
	result := s.db.Delete(&resourceTypes.NetworkResource{}, accountAndIDQueryCondition, accountID, resourceID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to delete network resource from store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to delete network resource from store")
	}

	if result.RowsAffected == 0 {
		return status.NewNetworkResourceNotFoundError(resourceID)
	}

	return nil
}
