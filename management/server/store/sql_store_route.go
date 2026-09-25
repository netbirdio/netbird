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

	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/status"
)

func (s *SqlStore) getRoutes(ctx context.Context, accountID string) ([]route.Route, error) {
	const query = `SELECT id, account_id, public_id, network, domains, keep_route, net_id, description, peer, peer_groups, network_type, masquerade, metric, enabled, groups, access_control_groups, skip_auto_apply FROM routes WHERE account_id = $1`
	rows, err := s.pool.Query(ctx, query, accountID)
	if err != nil {
		return nil, err
	}
	routes, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (route.Route, error) {
		var r route.Route
		var network, domains, peerGroups, groups, accessGroups []byte
		var keepRoute, masquerade, enabled, skipAutoApply sql.NullBool
		var metric sql.NullInt64
		err := row.Scan(&r.ID, &r.AccountID, &r.PublicID, &network, &domains, &keepRoute, &r.NetID, &r.Description, &r.Peer, &peerGroups, &r.NetworkType, &masquerade, &metric, &enabled, &groups, &accessGroups, &skipAutoApply)
		if err == nil {
			if keepRoute.Valid {
				r.KeepRoute = keepRoute.Bool
			}
			if masquerade.Valid {
				r.Masquerade = masquerade.Bool
			}
			if enabled.Valid {
				r.Enabled = enabled.Bool
			}
			if skipAutoApply.Valid {
				r.SkipAutoApply = skipAutoApply.Bool
			}
			if metric.Valid {
				r.Metric = int(metric.Int64)
			}
			if network != nil {
				_ = json.Unmarshal(network, &r.Network)
			}
			if domains != nil {
				_ = json.Unmarshal(domains, &r.Domains)
			}
			if peerGroups != nil {
				_ = json.Unmarshal(peerGroups, &r.PeerGroups)
			}
			if groups != nil {
				_ = json.Unmarshal(groups, &r.Groups)
			}
			if accessGroups != nil {
				_ = json.Unmarshal(accessGroups, &r.AccessControlGroups)
			}
		}
		return r, err
	})
	if err != nil {
		return nil, err
	}
	return routes, nil
}

// GetAccountRoutes retrieves network routes for an account.
func (s *SqlStore) GetAccountRoutes(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*route.Route, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var routes []*route.Route
	result := tx.Find(&routes, accountIDCondition, accountID)
	if err := result.Error; err != nil {
		log.WithContext(ctx).Errorf("failed to get routes from the store: %s", err)
		return nil, status.Errorf(status.Internal, "failed to get routes from store")
	}

	return routes, nil
}

// GetRouteByID retrieves a route by its ID and account ID.
func (s *SqlStore) GetRouteByID(ctx context.Context, lockStrength LockingStrength, accountID string, routeID string) (*route.Route, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var route *route.Route
	result := tx.Take(&route, accountAndIDQueryCondition, accountID, routeID)
	if err := result.Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.NewRouteNotFoundError(routeID)
		}
		log.WithContext(ctx).Errorf("failed to get route from the store: %s", err)
		return nil, status.Errorf(status.Internal, "failed to get route from store")
	}

	return route, nil
}

// GetRouteByIDOrPublicID retrieves a route by either its ID or its PublicID. See
// GetPolicyByIDOrPublicID for why peer-reported references need both.
func (s *SqlStore) GetRouteByIDOrPublicID(ctx context.Context, lockStrength LockingStrength, accountID string, routeID string) (*route.Route, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var route *route.Route
	result := tx.Take(&route, accountAndAnyIDQueryCondition, accountID, routeID, routeID)
	if err := result.Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.NewRouteNotFoundError(routeID)
		}
		log.WithContext(ctx).Errorf("failed to get route from the store: %s", err)
		return nil, status.Errorf(status.Internal, "failed to get route from store")
	}

	return route, nil
}

// SaveRoute saves a route to the database.
func (s *SqlStore) SaveRoute(ctx context.Context, route *route.Route) error {
	result := s.db.Save(route)
	if err := result.Error; err != nil {
		log.WithContext(ctx).Errorf("failed to save route to the store: %s", err)
		return status.Errorf(status.Internal, "failed to save route to store")
	}

	return nil
}

// DeleteRoute deletes a route from the database.
func (s *SqlStore) DeleteRoute(ctx context.Context, accountID, routeID string) error {
	result := s.db.Delete(&route.Route{}, accountAndIDQueryCondition, accountID, routeID)
	if err := result.Error; err != nil {
		log.WithContext(ctx).Errorf("failed to delete route from the store: %s", err)
		return status.Errorf(status.Internal, "failed to delete route from store")
	}

	if result.RowsAffected == 0 {
		return status.NewRouteNotFoundError(routeID)
	}

	return nil
}
