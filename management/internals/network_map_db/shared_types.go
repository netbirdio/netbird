package networkmapdb

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/miekg/dns"
	"github.com/netbirdio/netbird/shared/management/networkmap"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

var ErrDnsUnsupportedRecordType = errors.New("unsupported record type")

type Account struct {
	PeerLoginExpirationEnabled      sql.NullBool
	PeerLoginExpiration             sql.NullInt64
	PeerInactivityExpirationEnabled sql.NullBool
	PeerInactivityExpiration        sql.NullInt64
	DNSDomain                       sql.NullString
	IPv6EnabledGroups               []byte `nmap:"json"`
	RoutingPeerDNSResolutionEnabled sql.NullBool
	LazyConnectionEnabled           sql.NullBool
	AutoUpdateVersion               sql.NullString
	AutoUpdateAlways                sql.NullBool
	MetricsPushEnabled              sql.NullBool
}

type Domain struct {
	Domain        sql.NullString
	TargetCluster sql.NullString
}

type Service struct {
	Enabled      sql.NullBool
	Private      sql.NullBool
	AccessGroups []string
	ProxyCluster sql.NullString
	Domain       sql.NullString
}

type Zone struct {
	Id                   string `nmap:"skip"`
	Domain               sql.NullString
	SearchDomainDisabled sql.NullBool
	DistributionGroups   []byte         `nmap:"skip,json"`
	RecordName           sql.NullString `nmap:"skip"`
	RecordType           sql.NullString `nmap:"skip"`
	RecordClass          sql.NullString `nmap:"skip"`
	RecordTTL            sql.NullInt64  `nmap:"skip"`
	RecordRData          sql.NullString `nmap:"skip"`
}

type NameserverGroup struct {
	ID                   string
	PublicID             sql.NullString
	Name                 sql.NullString
	Description          sql.NullString
	NameServers          []byte `nmap:"json"`
	Groups               []byte `nmap:"json"`
	Primary              sql.NullBool
	Domains              []byte `nmap:"json"`
	Enabled              sql.NullBool
	SearchDomainsEnabled sql.NullBool
}

type Networkresource struct {
	ID          string
	NetworkID   sql.NullString
	AccountID   sql.NullString
	PublicID    sql.NullString
	Name        sql.NullString
	Description sql.NullString
	Type        sql.NullString
	Domain      sql.NullString
	Prefix      []byte `nmap:"json"`
	Enabled     sql.NullBool
}

type AccountNetwork struct {
	Identifier sql.NullString
	Net        []byte `nmap:"json"`
	NetV6      []byte `nmap:"json"`
	Dns        sql.NullString
	Serial     sql.NullInt64
}

func RecordTypeAndRdata(t, rdata string) (int, string, error) {
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

func ZonesToAppliedZoneCandidates(zones []Zone) ([]networkmap.AppliedZoneCandidate, error) {
	toret := make([]networkmap.AppliedZoneCandidate, 0, len(zones))
	currentZoneId := ""
	for _, z := range zones {
		if !z.RecordType.Valid {
			continue
		}

		zone := nmdata.CustomZone{}
		err := FromSqlTypesToSharedTypes(
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
			toret = append(toret, AppliedZoneCandidateFromZone(zone, distributionGroups))
			currentZoneId = z.Id
		}

		rtype, rdata, err := RecordTypeAndRdata(z.RecordType.String, z.RecordRData.String)
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

func AppliedZoneCandidateFromZone(z nmdata.CustomZone, distributionGroups []string) networkmap.AppliedZoneCandidate {
	return networkmap.AppliedZoneCandidate{
		DistributionGroups: distributionGroups,
		Zone:               z,
	}
}
