package networkmap_pgsql

import (
	"context"

	"github.com/jackc/pgx/v5"
	networkmapdb "github.com/netbirdio/netbird/management/internals/network_map_db"
	"github.com/netbirdio/netbird/shared/management/networkmap"
)

const (
	GetAccountZonesQuery = `
	select zones.id as id, domain, not enable_search_domain as search_domain_disabled, distribution_groups,
	r.name as record_name, r.type as record_type, 'IN' record_class, r.ttl as record_ttl, r.content as record_rdata
	from zones
	left join records as r on r.zone_id = zones.id
	where zones.account_id=$1 and zones.enabled
	order by zones.id
	`
)

func (pgc *PgStoreConn) GetAppliedZoneCandidates(ctx context.Context, accountId string) ([]networkmap.AppliedZoneCandidate, error) {
	rows, err := pgc.Conn.Query(ctx, GetAccountZonesQuery, accountId)
	if err != nil {
		return nil, err
	}

	zones, err := pgx.CollectRows(rows, pgx.RowToStructByName[networkmapdb.Zone])
	if err != nil {
		return nil, err
	}

	return networkmapdb.ZonesToAppliedZoneCandidates(zones)
}
