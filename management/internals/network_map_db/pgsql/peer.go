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
	select id, key, ssh_key, dns_label, extra_dns_labels, user_id, ssh_enabled, login_expiration_enabled, last_login, ip, ipv6,
	peer_status_requires_approval, peer_status_connected, proxy_meta_embedded, proxy_meta_cluster,
	meta_wt_version, meta_go_os, meta_os_version, meta_kernel_version, meta_network_addresses, meta_files, meta_capabilities, meta_flags, meta_sync_message_version,
	location_country_code, location_city_name, location_connection_ip
	from peers
	where account_id = $1
	`
)

func (pgc *PgStoreConn) GetPeers(ctx context.Context, accountId string) ([]nmdata.Peer, map[string][]*nmdata.Peer, error) {
	rows, err := pgc.Conn.Query(ctx, GetPeersQuery, accountId)
	if err != nil {
		return nil, nil, err
	}

	peers, err := pgx.CollectRows(rows, pgx.RowToStructByName[peer])
	if err != nil {
		return nil, nil, err
	}

	toret := make([]nmdata.Peer, 0, len(peers))
	clusterToPeerIdx := make(map[string][]*nmdata.Peer)
	for _, p := range peers {
		dp := nmdata.Peer{}
		err := networkmapdb.FromSqlTypesToSharedTypes(
			reflect.ValueOf(&p), reflect.ValueOf(&dp))
		if err != nil {
			return nil, nil, err
		}

		if p.ProxyMetaEmbedded.Valid {
			dp.ProxyMeta.Embedded = p.ProxyMetaEmbedded.Bool
		}
		// This is only used to build private service candidates, not connected peers are skipped
		if dp.ProxyMeta.Embedded && p.PeerStatusConnected.Bool {
			clusterToPeerIdx[p.ProxyMetaCluster.String] = append(clusterToPeerIdx[p.ProxyMetaCluster.String], &dp)
		}
		if p.MetaWtVersion.Valid {
			dp.Meta.WtVersion = p.MetaWtVersion.String
		}
		if p.MetaSyncMessageVersion.Valid {
			dp.Meta.SyncMessageVersion = int(p.MetaSyncMessageVersion.Int64)
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
				return toret, nil, err
			}
		}
		if p.MetaFiles != nil {
			err := json.Unmarshal(p.MetaFiles, &dp.Meta.Files)
			if err != nil {
				return toret, nil, err
			}
		}
		if p.MetaCapabilities != nil {
			err := json.Unmarshal(p.MetaCapabilities, &dp.Meta.Capabilities)
			if err != nil {
				return toret, nil, err
			}
		}
		if p.MetaFlags != nil {
			err := json.Unmarshal(p.MetaFlags, &dp.Meta.Flags)
			if err != nil {
				return toret, nil, err
			}
		}
		if p.MetaNetworkAddresses != nil {
			err := json.Unmarshal(p.MetaNetworkAddresses, &dp.Meta.NetworkAddresses)
			if err != nil {
				return toret, nil, err
			}
		}

		toret = append(toret, dp)
	}

	return toret, clusterToPeerIdx, nil
}

// TODO add support for creating struct fields from denormalized fields
type peer struct {
	ID                         string
	Key                        sql.NullString
	SSHKey                     sql.NullString
	DNSLabel                   sql.NullString
	ExtraDNSLabels             json.RawMessage
	UserID                     sql.NullString
	LastLogin                  sql.NullTime
	SSHEnabled                 sql.NullBool
	LoginExpirationEnabled     sql.NullBool
	PeerStatusConnected        sql.NullBool   `nmap:"skip"`
	PeerStatusRequiresApproval sql.NullBool   `nmap:"map_to:RequiresApproval"`
	ProxyMetaEmbedded          sql.NullBool   `nmap:"skip"`
	ProxyMetaCluster           sql.NullString `nmap:"skip"`
	IP                         json.RawMessage
	IPv6                       json.RawMessage
	LocationConnectionIp       json.RawMessage `nmap:"skip"`
	MetaFiles                  json.RawMessage `nmap:"skip"`
	MetaCapabilities           json.RawMessage `nmap:"skip"`
	MetaFlags                  json.RawMessage `nmap:"skip"`
	MetaNetworkAddresses       json.RawMessage `nmap:"skip"`
	MetaWtVersion              sql.NullString  `nmap:"skip"`
	MetaGoOS                   sql.NullString  `nmap:"skip"`
	MetaOSVersion              sql.NullString  `nmap:"skip"`
	MetaKernelVersion          sql.NullString  `nmap:"skip"`
	MetaSyncMessageVersion     sql.NullInt64   `nmap:"skip"`
	LocationCountryCode        sql.NullString  `nmap:"skip"`
	LocationCityName           sql.NullString  `nmap:"skip"`
}
