package store

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/jackc/pgx/v5"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm/clause"

	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

func (s *SqlStore) getPolicyRules(ctx context.Context, policyIDs []string) ([]*types.PolicyRule, error) {
	if len(policyIDs) == 0 {
		return nil, nil
	}
	const query = `SELECT id, policy_id, name, description, enabled, action, destinations, destination_resource, sources, source_resource, bidirectional, protocol, ports, port_ranges, authorized_groups, authorized_user FROM policy_rules WHERE policy_id = ANY($1)`
	rows, err := s.pool.Query(ctx, query, policyIDs)
	if err != nil {
		return nil, err
	}
	rules, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (*types.PolicyRule, error) {
		var r types.PolicyRule
		var dest, destRes, sources, sourceRes, ports, portRanges, authorizedGroups []byte
		var enabled, bidirectional sql.NullBool
		var authorizedUser sql.NullString
		err := row.Scan(&r.ID, &r.PolicyID, &r.Name, &r.Description, &enabled, &r.Action, &dest, &destRes, &sources, &sourceRes, &bidirectional, &r.Protocol, &ports, &portRanges, &authorizedGroups, &authorizedUser)
		if err == nil {
			if enabled.Valid {
				r.Enabled = enabled.Bool
			}
			if bidirectional.Valid {
				r.Bidirectional = bidirectional.Bool
			}
			if dest != nil {
				_ = json.Unmarshal(dest, &r.Destinations)
			}
			if destRes != nil {
				_ = json.Unmarshal(destRes, &r.DestinationResource)
			}
			if sources != nil {
				_ = json.Unmarshal(sources, &r.Sources)
			}
			if sourceRes != nil {
				_ = json.Unmarshal(sourceRes, &r.SourceResource)
			}
			if ports != nil {
				_ = json.Unmarshal(ports, &r.Ports)
			}
			if portRanges != nil {
				_ = json.Unmarshal(portRanges, &r.PortRanges)
			}
			if authorizedGroups != nil {
				_ = json.Unmarshal(authorizedGroups, &r.AuthorizedGroups)
			}
			if authorizedUser.Valid {
				r.AuthorizedUser = authorizedUser.String
			}
		}
		return &r, err
	})
	if err != nil {
		return nil, err
	}
	return rules, nil
}

func (s *SqlStore) GetPolicyRulesByResourceID(ctx context.Context, lockStrength LockingStrength, accountID string, resourceID string) ([]*types.PolicyRule, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var policyRules []*types.PolicyRule
	resourceIDPattern := `%"ID":"` + resourceID + `"%`
	result := tx.Where("source_resource LIKE ? OR destination_resource LIKE ?", resourceIDPattern, resourceIDPattern).
		Find(&policyRules)

	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get policy rules for resource id from store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get policy rules for resource id from store")
	}

	return policyRules, nil
}
