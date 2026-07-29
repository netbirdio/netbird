package networkmap_pgsql

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"

	"github.com/jackc/pgx/v5"
	networkmapdb "github.com/netbirdio/netbird/management/internals/network_map_db"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

const (
	GetPoliciesQuery = `
	select p.id, p.public_id, p.enabled, p.source_posture_checks, pr.enabled as rule_enabled, pr.action, pr.protocol, pr.bidirectional, 
	pr.sources, pr.destinations, pr.source_resource, pr.destination_resource, pr.ports, pr.port_ranges,
	pr.authorized_groups, pr.authorized_user
	from policies as p
	left join policy_rules as pr on p.id = pr.policy_id 
	where account_id=$1
	`
)

func (pg *PgStore) GetPolicies(ctx context.Context, accountId string) ([]nmdata.Policy, error) {
	rows, err := pg.pool.Query(ctx, GetPoliciesQuery, accountId)
	if err != nil {
		return nil, err
	}

	policies, err := pgx.CollectRows(rows, pgx.RowToStructByName[policy])
	if err != nil {
		return nil, err
	}

	toret := make([]nmdata.Policy, 0, len(policies))
	for _, p := range policies {
		policy := nmdata.Policy{}
		err := networkmapdb.FromSqlTypesToSharedTypes(
			reflect.ValueOf(&p).Elem(), reflect.ValueOf(&policy).Elem())
		if err != nil {
			return nil, err
		}

		var policyRule *nmdata.PolicyRule
		pr := func() *nmdata.PolicyRule {
			if policyRule != nil {
				return policyRule
			}

			policyRule = &nmdata.PolicyRule{}
			return policyRule
		}

		if p.RuleEnabled.Valid {
			pr().Enabled = p.RuleEnabled.Bool
		}
		if p.Action.Valid {
			pr().Action = p.Action.String
		}
		if p.Protocol.Valid {
			pr().Protocol = p.Protocol.String
		}
		if p.Bidirectional.Valid {
			pr().Bidirectional = p.Bidirectional.Bool
		}
		if len(p.Sources) > 0 {
			err := json.Unmarshal([]byte(p.Sources), &pr().Sources)
			if err != nil {
				return toret, err
			}
		}
		if len(p.Destinations) > 0 {
			err := json.Unmarshal([]byte(p.Destinations), &pr().Destinations)
			if err != nil {
				return toret, err
			}
		}
		if len(p.SourceResource) > 0 {
			err := json.Unmarshal([]byte(p.SourceResource), &pr().SourceResource)
			if err != nil {
				return toret, err
			}
		}
		if len(p.DestinationResource) > 0 {
			err := json.Unmarshal([]byte(p.DestinationResource), &pr().DestinationResource)
			if err != nil {
				return toret, err
			}
		}
		if len(p.Ports) > 0 {
			err := json.Unmarshal([]byte(p.Ports), &pr().Ports)
			if err != nil {
				return toret, err
			}
		}
		if len(p.PortRanges) > 0 {
			err := json.Unmarshal([]byte(p.PortRanges), &pr().PortRanges)
			if err != nil {
				return toret, err
			}
		}
		if len(p.AuthorizedGroups) > 0 {
			err := json.Unmarshal([]byte(p.AuthorizedGroups), &pr().AuthorizedGroups)
			if err != nil {
				return toret, err
			}
		}
		if p.AuthorizedUser.Valid {
			pr().AuthorizedUser = p.AuthorizedUser.String
		}

		if policyRule != nil {
			policyRule.ID = p.ID
			policyRule.PolicyID = p.ID
			policy.Rules = []*nmdata.PolicyRule{policyRule}
		}

		toret = append(toret, policy)
	}

	return toret, err
}

type policy struct {
	ID                  string
	PublicID            sql.NullString
	SourcePostureChecks json.RawMessage
	Enabled             sql.NullBool
	RuleEnabled         sql.NullBool    `nmap:"skip"`
	Bidirectional       sql.NullBool    `nmap:"skip"`
	Action              sql.NullString  `nmap:"skip"`
	Protocol            sql.NullString  `nmap:"skip"`
	Sources             json.RawMessage `nmap:"skip"`
	Destinations        json.RawMessage `nmap:"skip"`
	SourceResource      json.RawMessage `nmap:"skip"`
	DestinationResource json.RawMessage `nmap:"skip"`
	Ports               json.RawMessage `nmap:"skip"`
	PortRanges          json.RawMessage `nmap:"skip"`
	AuthorizedGroups    json.RawMessage `nmap:"skip"`
	AuthorizedUser      sql.NullString  `nmap:"skip"`
}
