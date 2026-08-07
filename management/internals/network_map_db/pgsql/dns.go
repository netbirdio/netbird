package networkmap_pgsql

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/jackc/pgx/v5"
	"github.com/miekg/dns"
	networkmapdb "github.com/netbirdio/netbird/management/internals/network_map_db"
	"github.com/netbirdio/netbird/shared/management/networkmap"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

var ErrDnsUnsupportedRecordType = errors.New("unsupported record type")

const (
	GetAccountZonesQuery = `
	select zones.id as id, domain, not enable_search_domain as search_domain_disabled, distribution_groups,
	r.name as record_name, r.type as record_type, 'IN' record_class, r.ttl as record_ttl, r.content as record_rdata
	from zones
	left join records as r on r.zone_id = zones.id 
	where zones.account_id=$1
	`
)

func (pgc *PgStoreConn) GetAppliedZoneCandidates(ctx context.Context, accountId string) ([]networkmap.AppliedZoneCandidate, error) {
	rows, err := pgc.Conn.Query(ctx, GetAccountZonesQuery, accountId)
	if err != nil {
		return nil, err
	}

	zones, err := pgx.CollectRows(rows, pgx.RowToStructByName[zone])
	if err != nil {
		return nil, err
	}

	toret := make([]networkmap.AppliedZoneCandidate, 0, len(zones))
	currentZoneId := ""
	for _, z := range zones {
		if !z.RecordType.Valid {
			continue
		}

		zone := nmdata.CustomZone{}
		err := networkmapdb.FromSqlTypesToSharedTypes(
			reflect.ValueOf(&z), reflect.ValueOf(&zone))
		if err != nil {
			return nil, err
		}

		var distributionGroups []string
		if err := json.Unmarshal(z.DistributionGroups, &distributionGroups); err != nil {
			return nil, err
		}

		if z.Id != currentZoneId {
			zone.Records = []nmdata.SimpleRecord{}
			toret = append(toret, appliedZoneCandidateFromZone(zone, distributionGroups))
			currentZoneId = z.Id
		}

		rtype, rdata, err := recordTypeAndRdata(z.RecordType.String, z.RecordRData.String)
		if err != nil {
			if errors.Is(err, ErrDnsUnsupportedRecordType) {
				continue
			}
			return nil, err
		}

		lastZone := &toret[len(toret)-1]
		lastZone.Zone.Records = append(lastZone.Zone.Records, nmdata.SimpleRecord{
			Name:  z.RecordName.String,
			Class: z.RecordClass.String,
			TTL:   int(z.RecordTTL.Int64),
			RData: rdata,
			Type:  rtype,
		})
	}
	return toret, nil
}

type zone struct {
	Id                   string          `nmap:"skip"`
	DistributionGroups   json.RawMessage `nmap:"skip"`
	Domain               sql.NullString
	SearchDomainDisabled sql.NullBool
	RecordName           sql.NullString `nmap:"skip"`
	RecordType           sql.NullString `nmap:"skip"`
	RecordClass          sql.NullString `nmap:"skip"`
	RecordTTL            sql.NullInt64  `nmap:"skip"`
	RecordRData          sql.NullString `nmap:"skip"`
}

func recordTypeAndRdata(t, rdata string) (int, string, error) {
	switch t {
	case "A":
		return int(dns.TypeA), rdata, nil
	case "AAAA":
		return int(dns.TypeAAAA), rdata, nil
	case "CNAME":
		return int(dns.TypeCNAME), dns.Fqdn(rdata), nil
	default:
		return 0, "", fmt.Errorf("record type: %s %w", t, ErrDnsUnsupportedRecordType)
	}
}

func appliedZoneCandidateFromZone(z nmdata.CustomZone, distributionGroups []string) networkmap.AppliedZoneCandidate {
	return networkmap.AppliedZoneCandidate{
		DistributionGroups: distributionGroups,
		Zone:               z,
	}
}
