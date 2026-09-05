package networkmap_pgsql

import (
	"context"

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

func (pgc *PgStoreConn) GetPolicies(ctx context.Context, accountId string) ([]nmdata.Policy, map[string]map[string]any, map[string]map[string]any, error) {
	rows, err := pgc.Conn.Query(ctx, GetPoliciesQuery, accountId)
	if err != nil {
		return nil, nil, nil, err
	}

	policies, err := pgx.CollectRows(rows, pgx.RowToStructByName[networkmapdb.Policy])
	if err != nil {
		return nil, nil, nil, err
	}

	return networkmapdb.ConvertToNmdataPolicy(policies)
}
