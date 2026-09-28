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

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/shared/management/status"
)

func (s *SqlStore) getNameServerGroups(ctx context.Context, accountID string) ([]nbdns.NameServerGroup, error) {
	const query = `SELECT id, account_id, public_id, name, description, name_servers, groups, "primary", domains, enabled, search_domains_enabled FROM name_server_groups WHERE account_id = $1`
	rows, err := s.pool.Query(ctx, query, accountID)
	if err != nil {
		return nil, err
	}
	nsgs, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (nbdns.NameServerGroup, error) {
		var n nbdns.NameServerGroup
		var ns, groups, domains []byte
		var primary, enabled, searchDomainsEnabled sql.NullBool
		err := row.Scan(&n.ID, &n.AccountID, &n.PublicID, &n.Name, &n.Description, &ns, &groups, &primary, &domains, &enabled, &searchDomainsEnabled)
		if err == nil {
			if primary.Valid {
				n.Primary = primary.Bool
			}
			if enabled.Valid {
				n.Enabled = enabled.Bool
			}
			if searchDomainsEnabled.Valid {
				n.SearchDomainsEnabled = searchDomainsEnabled.Bool
			}
			if ns != nil {
				_ = json.Unmarshal(ns, &n.NameServers)
			} else {
				n.NameServers = []nbdns.NameServer{}
			}
			if groups != nil {
				_ = json.Unmarshal(groups, &n.Groups)
			} else {
				n.Groups = []string{}
			}
			if domains != nil {
				_ = json.Unmarshal(domains, &n.Domains)
			} else {
				n.Domains = []string{}
			}
		}
		return n, err
	})
	if err != nil {
		return nil, err
	}
	return nsgs, nil
}

// GetAccountNameServerGroups retrieves name server groups for an account.
func (s *SqlStore) GetAccountNameServerGroups(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*nbdns.NameServerGroup, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var nsGroups []*nbdns.NameServerGroup
	result := tx.Find(&nsGroups, accountIDCondition, accountID)
	if err := result.Error; err != nil {
		log.WithContext(ctx).Errorf("failed to get name server groups from the store: %s", err)
		return nil, status.Errorf(status.Internal, "failed to get name server groups from store")
	}

	return nsGroups, nil
}

// GetNameServerGroupByID retrieves a name server group by its ID and account ID.
func (s *SqlStore) GetNameServerGroupByID(ctx context.Context, lockStrength LockingStrength, accountID, nsGroupID string) (*nbdns.NameServerGroup, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var nsGroup *nbdns.NameServerGroup
	result := tx.
		Take(&nsGroup, accountAndIDQueryCondition, accountID, nsGroupID)
	if err := result.Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.NewNameServerGroupNotFoundError(nsGroupID)
		}
		log.WithContext(ctx).Errorf("failed to get name server group from the store: %s", err)
		return nil, status.Errorf(status.Internal, "failed to get name server group from store")
	}

	return nsGroup, nil
}

// SaveNameServerGroup saves a name server group to the database.
func (s *SqlStore) SaveNameServerGroup(ctx context.Context, nameServerGroup *nbdns.NameServerGroup) error {
	result := s.db.Save(nameServerGroup)
	if err := result.Error; err != nil {
		log.WithContext(ctx).Errorf("failed to save name server group to the store: %s", err)
		return status.Errorf(status.Internal, "failed to save name server group to store")
	}
	return nil
}

// DeleteNameServerGroup deletes a name server group from the database.
func (s *SqlStore) DeleteNameServerGroup(ctx context.Context, accountID, nsGroupID string) error {
	result := s.db.Delete(&nbdns.NameServerGroup{}, accountAndIDQueryCondition, accountID, nsGroupID)
	if err := result.Error; err != nil {
		log.WithContext(ctx).Errorf("failed to delete name server group from the store: %s", err)
		return status.Errorf(status.Internal, "failed to delete name server group from store")
	}

	if result.RowsAffected == 0 {
		return status.NewNameServerGroupNotFoundError(nsGroupID)
	}

	return nil
}
