package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	networkTypes "github.com/netbirdio/netbird/management/server/networks/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

func (s *SqlStore) getNetworks(ctx context.Context, accountID string) ([]*networkTypes.Network, error) {
	const query = `SELECT id, account_id, public_id, name, description FROM networks WHERE account_id = $1`
	rows, err := s.pool.Query(ctx, query, accountID)
	if err != nil {
		return nil, err
	}
	networks, err := pgx.CollectRows(rows, pgx.RowToStructByName[networkTypes.Network])
	if err != nil {
		return nil, err
	}
	result := make([]*networkTypes.Network, len(networks))
	for i := range networks {
		result[i] = &networks[i]
	}
	return result, nil
}

func (s *SqlStore) GetAccountNetworks(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*networkTypes.Network, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var networks []*networkTypes.Network
	result := tx.Find(&networks, accountIDCondition, accountID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get networks from the store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get networks from store")
	}

	return networks, nil
}

func (s *SqlStore) GetNetworkByID(ctx context.Context, lockStrength LockingStrength, accountID, networkID string) (*networkTypes.Network, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var network *networkTypes.Network
	result := tx.Take(&network, accountAndIDQueryCondition, accountID, networkID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.NewNetworkNotFoundError(networkID)
		}

		log.WithContext(ctx).Errorf("failed to get network from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get network from store")
	}

	return network, nil
}

func (s *SqlStore) SaveNetwork(ctx context.Context, network *networkTypes.Network) error {
	result := s.db.Save(network)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to save network to store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to save network to store")
	}

	return nil
}

func (s *SqlStore) DeleteNetwork(ctx context.Context, accountID, networkID string) error {
	result := s.db.Delete(&networkTypes.Network{}, accountAndIDQueryCondition, accountID, networkID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to delete network from store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to delete network from store")
	}

	if result.RowsAffected == 0 {
		return status.NewNetworkNotFoundError(networkID)
	}

	return nil
}
