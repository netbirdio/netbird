package networkmap_pgsql

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/jackc/pgx/v5"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

const (
	GetPoliciesQuery = `
	select p.id, p.public_id, p.enabled, p.source_posture_checks, pr.enabled, pr.action, pr.protocol, pr.bidirectional, 
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

	var (
		publicId, sourcePostureChecks                          sql.NullString
		enabled, ruleEnabled, bidirectional                    sql.NullBool
		action, protocol, sources, destinations                sql.NullString
		sourceResource, destinationResource, ports, portRanges sql.NullString
		authorizedGroups, authorizedUser                       sql.NullString
	)

	policies, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (nmdata.Policy, error) {
		var policy nmdata.Policy
		var policyRule *nmdata.PolicyRule

		pr := func() *nmdata.PolicyRule {
			if policyRule != nil {
				return policyRule
			}

			policyRule = &nmdata.PolicyRule{}
			return policyRule
		}

		err := row.Scan(&policy.ID, &publicId, &enabled, &sourcePostureChecks, &ruleEnabled, &action, &protocol, &bidirectional,
			&sources, &destinations, &sourceResource, &destinationResource, &ports, &portRanges,
			&authorizedGroups, &authorizedUser)
		if err != nil {
			return policy, err
		}

		if publicId.Valid {
			policy.PublicID = publicId.String
		}
		if sourcePostureChecks.Valid {
			err := json.Unmarshal([]byte(sourcePostureChecks.String), &policy.SourcePostureChecks)
			if err != nil {
				return policy, err
			}
		}
		if enabled.Valid {
			policy.Enabled = enabled.Bool
		}
		if ruleEnabled.Valid {
			pr().Enabled = ruleEnabled.Bool
		}
		if action.Valid {
			pr().Action = action.String
		}
		if protocol.Valid {
			pr().Protocol = protocol.String
		}
		if bidirectional.Valid {
			pr().Bidirectional = bidirectional.Bool
		}
		if sources.Valid {
			err := json.Unmarshal([]byte(sources.String), &pr().Sources)
			if err != nil {
				return policy, err
			}
		}
		if destinations.Valid {
			err := json.Unmarshal([]byte(destinations.String), &pr().Destinations)
			if err != nil {
				return policy, err
			}
		}
		if sourceResource.Valid {
			err := json.Unmarshal([]byte(sourceResource.String), &pr().SourceResource)
			if err != nil {
				return policy, err
			}
		}
		if destinationResource.Valid {
			err := json.Unmarshal([]byte(destinationResource.String), &pr().DestinationResource)
			if err != nil {
				return policy, err
			}
		}
		if ports.Valid {
			err := json.Unmarshal([]byte(ports.String), &pr().Ports)
			if err != nil {
				return policy, err
			}
		}
		if portRanges.Valid {
			err := json.Unmarshal([]byte(portRanges.String), &pr().PortRanges)
			if err != nil {
				return policy, err
			}
		}
		if authorizedGroups.Valid {
			err := json.Unmarshal([]byte(authorizedGroups.String), &pr().AuthorizedGroups)
			if err != nil {
				return policy, err
			}
		}
		if authorizedUser.Valid {
			pr().AuthorizedUser = authorizedUser.String
		}

		if policyRule != nil {
			policyRule.ID = policy.ID
			policyRule.PolicyID = policy.ID
			policy.Rules = []*nmdata.PolicyRule{policyRule}
		}

		return policy, nil
	})

	return policies, err
}
