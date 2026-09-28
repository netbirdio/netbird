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

	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	networkTypes "github.com/netbirdio/netbird/management/server/networks/types"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

func (s *SqlStore) getNetworkRouters(ctx context.Context, accountID string) ([]*routerTypes.NetworkRouter, error) {
	const query = `SELECT id, network_id, account_id, public_id, peer, peer_groups, masquerade, metric, enabled FROM network_routers WHERE account_id = $1`
	rows, err := s.pool.Query(ctx, query, accountID)
	if err != nil {
		return nil, err
	}
	routers, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (routerTypes.NetworkRouter, error) {
		var r routerTypes.NetworkRouter
		var peerGroups []byte
		var masquerade, enabled sql.NullBool
		var metric sql.NullInt64
		err := row.Scan(&r.ID, &r.NetworkID, &r.AccountID, &r.PublicID, &r.Peer, &peerGroups, &masquerade, &metric, &enabled)
		if err == nil {
			if masquerade.Valid {
				r.Masquerade = masquerade.Bool
			}
			if enabled.Valid {
				r.Enabled = enabled.Bool
			}
			if metric.Valid {
				r.Metric = int(metric.Int64)
			}
			if peerGroups != nil {
				_ = json.Unmarshal(peerGroups, &r.PeerGroups)
			}
		}
		return r, err
	})
	if err != nil {
		return nil, err
	}
	result := make([]*routerTypes.NetworkRouter, len(routers))
	for i := range routers {
		result[i] = &routers[i]
	}
	return result, nil
}

func (s *SqlStore) GetNetworkRoutersByNetID(ctx context.Context, lockStrength LockingStrength, accountID, netID string) ([]*routerTypes.NetworkRouter, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var netRouters []*routerTypes.NetworkRouter
	result := tx.
		Find(&netRouters, "account_id = ? AND network_id = ?", accountID, netID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get network routers from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get network routers from store")
	}

	return netRouters, nil
}

func (s *SqlStore) GetNetworkRoutersByAccountID(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*routerTypes.NetworkRouter, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var netRouters []*routerTypes.NetworkRouter
	result := tx.
		Find(&netRouters, accountIDCondition, accountID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get network routers from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get network routers from store")
	}

	return netRouters, nil
}

func (s *SqlStore) GetNetworkRouterByID(ctx context.Context, lockStrength LockingStrength, accountID, routerID string) (*routerTypes.NetworkRouter, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var netRouter *routerTypes.NetworkRouter
	result := tx.
		Take(&netRouter, accountAndIDQueryCondition, accountID, routerID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.NewNetworkRouterNotFoundError(routerID)
		}
		log.WithContext(ctx).Errorf("failed to get network router from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get network router from store")
	}

	return netRouter, nil
}

func (s *SqlStore) CreateNetworkRouter(ctx context.Context, router *routerTypes.NetworkRouter) error {
	if err := s.db.Create(router).Error; err != nil {
		log.WithContext(ctx).Errorf("failed to create network router in store: %v", err)
		return status.Errorf(status.Internal, "failed to create network router in store")
	}

	return nil
}

func (s *SqlStore) UpdateNetworkRouter(ctx context.Context, router *routerTypes.NetworkRouter) error {
	result := s.db.
		Select("*").
		Where(accountAndIDQueryCondition, router.AccountID, router.ID).
		Updates(router)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to update network router in store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to update network router in store")
	}

	if result.RowsAffected == 0 {
		return status.NewNetworkRouterNotFoundError(router.ID)
	}

	return nil
}

func (s *SqlStore) DeleteNetworkRouter(ctx context.Context, accountID, routerID string) error {
	result := s.db.Delete(&routerTypes.NetworkRouter{}, accountAndIDQueryCondition, accountID, routerID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to delete network router from store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to delete network router from store")
	}

	if result.RowsAffected == 0 {
		return status.NewNetworkRouterNotFoundError(routerID)
	}

	return nil
}

// GetRoutingPeerNetworks returns the distinct network names where the peer is assigned as a routing peer
// in an enabled network router, either directly or via peer groups.
func (s *SqlStore) GetRoutingPeerNetworks(_ context.Context, accountID, peerID string) ([]string, error) {
	var routers []*routerTypes.NetworkRouter
	if err := s.db.Select("peer, peer_groups, network_id").Where("account_id = ? AND enabled = true", accountID).Find(&routers).Error; err != nil {
		return nil, status.Errorf(status.Internal, "failed to get enabled routers: %v", err)
	}

	if len(routers) == 0 {
		return nil, nil
	}

	var groupPeers []types.GroupPeer
	if err := s.db.Select("group_id").Where("account_id = ? AND peer_id = ?", accountID, peerID).Find(&groupPeers).Error; err != nil {
		return nil, status.Errorf(status.Internal, "failed to get peer group memberships: %v", err)
	}

	groupSet := make(map[string]struct{}, len(groupPeers))
	for _, gp := range groupPeers {
		groupSet[gp.GroupID] = struct{}{}
	}

	networkIDs := make(map[string]struct{})
	for _, r := range routers {
		if r.Peer == peerID {
			networkIDs[r.NetworkID] = struct{}{}
		} else if r.Peer == "" {
			for _, pg := range r.PeerGroups {
				if _, ok := groupSet[pg]; ok {
					networkIDs[r.NetworkID] = struct{}{}
					break
				}
			}
		}
	}

	if len(networkIDs) == 0 {
		return nil, nil
	}

	ids := make([]string, 0, len(networkIDs))
	for id := range networkIDs {
		ids = append(ids, id)
	}

	var networks []*networkTypes.Network
	if err := s.db.Select("name").Where("account_id = ? AND id IN ?", accountID, ids).Find(&networks).Error; err != nil {
		return nil, status.Errorf(status.Internal, "failed to get networks: %v", err)
	}

	names := make([]string, 0, len(networks))
	for _, n := range networks {
		names = append(names, n.Name)
	}

	return names, nil
}
