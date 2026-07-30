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
	GetPeersQuery = `
	select id, key, ssh_key, dns_label, user_id, ssh_enabled, login_expiration_enabled, last_login, ip, ipv6,
	meta_wt_version, meta_go_os, meta_os_version, meta_kernel_version, meta_network_addresses, meta_files, meta_capabilities, meta_flags, 
	location_country_code, location_city_name, location_connection_ip
	from peers
	where account_id = $1
	`
)

func (pg *PgStore) GetPeers(ctx context.Context, accountId string) ([]nmdata.Peer, error) {
	rows, err := pg.pool.Query(ctx, GetPeersQuery, accountId)
	if err != nil {
		return nil, err
	}

	peers, err := pgx.CollectRows(rows, pgx.RowToStructByName[peer])
	if err != nil {
		return nil, err
	}

	toret := make([]nmdata.Peer, 0, len(peers))
	for _, p := range peers {
		dp := nmdata.Peer{}
		err := networkmapdb.FromSqlTypesToSharedTypes(
			reflect.ValueOf(&p), reflect.ValueOf(&dp))
		if err != nil {
			return nil, err
		}

		if p.MetaWtVersion.Valid {
			dp.Meta.WtVersion = p.MetaWtVersion.String
		}
		if p.MetaGoOS.Valid {
			dp.Meta.GoOS = p.MetaGoOS.String
		}
		if p.MetaOSVersion.Valid {
			dp.Meta.OSVersion = p.MetaOSVersion.String
		}
		if p.MetaKernelVersion.Valid {
			dp.Meta.KernelVersion = p.MetaKernelVersion.String
		}
		if p.LocationCountryCode.Valid {
			dp.Location.CountryCode = p.LocationCountryCode.String
		}
		if p.LocationCityName.Valid {
			dp.Location.CityName = p.LocationCityName.String
		}
		if p.LocationConnectionIp != nil {
			err := json.Unmarshal(p.LocationConnectionIp, &dp.Location.ConnectionIP)
			if err != nil {
				return toret, err
			}
		}
		if p.MetaFiles != nil {
			err := json.Unmarshal(p.MetaFiles, &dp.Meta.Files)
			if err != nil {
				return toret, err
			}
		}
		if p.MetaCapabilities != nil {
			err := json.Unmarshal(p.MetaCapabilities, &dp.Meta.Capabilities)
			if err != nil {
				return toret, err
			}
		}
		if p.MetaFlags != nil {
			err := json.Unmarshal(p.MetaFlags, &dp.Meta.Flags)
			if err != nil {
				return toret, err
			}
		}
		if p.MetaNetworkAddresses != nil {
			err := json.Unmarshal(p.MetaNetworkAddresses, &dp.Meta.NetworkAddresses)
			if err != nil {
				return toret, err
			}
		}
	}

	return toret, nil
}

// TODO add support for creating struct fields from denormalized fields
type peer struct {
	ID                     string
	Key                    sql.NullString
	SSHKey                 sql.NullString
	DNSLabel               sql.NullString
	UserID                 sql.NullString
	LastLogin              sql.NullTime
	SSHEnabled             sql.NullBool
	LoginExpirationEnabled sql.NullBool
	IP                     json.RawMessage
	IPv6                   json.RawMessage
	LocationConnectionIp   json.RawMessage `nmap:"skip"`
	MetaFiles              json.RawMessage `nmap:"skip"`
	MetaCapabilities       json.RawMessage `nmap:"skip"`
	MetaFlags              json.RawMessage `nmap:"skip"`
	MetaNetworkAddresses   json.RawMessage `nmap:"skip"`
	MetaWtVersion          sql.NullString  `nmap:"skip"`
	MetaGoOS               sql.NullString  `nmap:"skip"`
	MetaOSVersion          sql.NullString  `nmap:"skip"`
	MetaKernelVersion      sql.NullString  `nmap:"skip"`
	LocationCountryCode    sql.NullString  `nmap:"skip"`
	LocationCityName       sql.NullString  `nmap:"skip"`
}
