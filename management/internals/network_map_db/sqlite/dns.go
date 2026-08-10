package networkmap_sqlite

import (
	"context"

	networkmapdb "github.com/netbirdio/netbird/management/internals/network_map_db"
	"github.com/netbirdio/netbird/shared/management/networkmap"
)

const (
	GetAccountZonesQuery = `
	select zones.id as id, domain, not enable_search_domain as search_domain_disabled, distribution_groups,
	r.name as record_name, r.type as record_type, 'IN' record_class, r.ttl as record_ttl, r.content as record_rdata
	from zones
	left join records as r on r.zone_id = zones.id 
	where zones.account_id=$1
	`
)

func (sc *SqliteStoreConn) GetAppliedZoneCandidates(ctx context.Context, accountId string) ([]networkmap.AppliedZoneCandidate, error) {
	rows, err := sc.Conn.QueryContext(ctx, GetAccountZonesQuery, accountId)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	zones := make([]networkmapdb.Zone, 0)
	for rows.Next() {
		z := networkmapdb.Zone{}
		err := rows.Scan(networkmapdb.StructFields(&z)...)
		if err != nil {
			return nil, err
		}
		zones = append(zones, z)
	}

	return networkmapdb.ZonesToAppliedZoneCandidates(zones)
}
