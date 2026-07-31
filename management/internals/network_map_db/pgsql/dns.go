package networkmap_pgsql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"reflect"

	"github.com/jackc/pgx/v5"
	"github.com/miekg/dns"
	networkmapdb "github.com/netbirdio/netbird/management/internals/network_map_db"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

var DnsUnsupportedRecordTypeError = errors.New("unsupported record type")

const (
	GetAccountZonesQuery = `
	select zones.id as id, domain, enable_search_domain as search_domain_disabled,
	r.name as record_name, r.type as record_type, 'IN' record_class, r.ttl as record_ttl, r.content as record_rdata
	from zones
	left join records as r on r.zone_id = zones.id 
	where zones.account_id=$1
	`
)

func (pg *PgStore) GetAccountZones(ctx context.Context, accountId string) ([]nmdata.CustomZone, error) {
	c, err := pg.Pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	return GetAccountZonesViaPgxConnection(ctx, c.Conn(), accountId)
}

func GetAccountZonesViaPgxConnection(ctx context.Context, conn *pgx.Conn, accountId string) ([]nmdata.CustomZone, error) {
	rows, err := conn.Query(ctx, GetAccountZonesQuery, accountId)
	if err != nil {
		return nil, err
	}

	zones, err := pgx.CollectRows(rows, pgx.RowToStructByName[zone])
	if err != nil {
		return nil, err
	}

	toret := make([]nmdata.CustomZone, 0, len(zones))
	currentZoneId := ""
	for _, z := range zones {
		zone := nmdata.CustomZone{}
		err := networkmapdb.FromSqlTypesToSharedTypes(
			reflect.ValueOf(&z), reflect.ValueOf(&zone))
		if err != nil {
			return nil, err
		}

		rtype, rdata, err := recordTypeAndRdata(z.RecordType.String, z.RecordRData.String)
		if err != nil {
			return nil, err
		}
		record := nmdata.SimpleRecord{
			Name:  z.RecordName.String,
			Class: z.RecordClass.String,
			TTL:   int(z.RecordTTL.Int64),
			RData: rdata,
			Type:  rtype,
		}
		zone.Records = []nmdata.SimpleRecord{record}

		if len(toret) == 0 {
			toret = append(toret, zone)
			currentZoneId = z.Id
			continue
		}

		if z.Id == currentZoneId {
			lastZone := &toret[len(toret)-1]
			lastZone.Records = append(lastZone.Records, record)
			continue
		}

		toret = append(toret, zone)
		currentZoneId = z.Id
	}
	return toret, nil
}

type zone struct {
	Id                   string `nmap:"skip"`
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
		return 0, "", fmt.Errorf("record type: %s %w", t, DnsUnsupportedRecordTypeError)
	}
}
