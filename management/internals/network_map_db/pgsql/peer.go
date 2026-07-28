package networkmap_pgsql

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/jackc/pgx/v5"
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

	var (
		id, key, sshKey, dnsLabel, userId                            sql.NullString
		lastLogin                                                    sql.NullTime
		sshEnabled, loginExpirationEnabled                           sql.NullBool
		ip, ipv6, locationConnectionIp                               []byte
		metaFiles, metaCapabilities, metaFlags, metaNetworkAddresses []byte
		metaWtVersion, metaGoOS, metaOSVersion, metaKernelVersion    sql.NullString
		locationCountryCode, locationCityName                        sql.NullString
	)

	peers, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (nmdata.Peer, error) {
		var peer nmdata.Peer
		err := row.Scan(&id, &key, &sshKey, &dnsLabel, &userId, &sshEnabled, &loginExpirationEnabled, &lastLogin, &ip, &ipv6,
			&metaWtVersion, &metaGoOS, &metaOSVersion, &metaKernelVersion, &metaNetworkAddresses, &metaFiles, &metaCapabilities, &metaFlags,
			&locationCountryCode, &locationCityName, &locationConnectionIp)
		if err != nil {
			return peer, err
		}

		if id.Valid {
			peer.ID = id.String
		}
		if key.Valid {
			peer.Key = key.String
		}
		if sshKey.Valid {
			peer.SSHKey = sshKey.String
		}
		if dnsLabel.Valid {
			peer.DNSLabel = dnsLabel.String
		}
		if userId.Valid {
			peer.UserID = userId.String
		}
		if lastLogin.Valid {
			peer.LastLogin = &lastLogin.Time
		}
		if sshEnabled.Valid {
			peer.SSHEnabled = sshEnabled.Bool
		}
		if loginExpirationEnabled.Valid {
			peer.LoginExpirationEnabled = loginExpirationEnabled.Bool
		}
		if metaWtVersion.Valid {
			peer.Meta.WtVersion = metaWtVersion.String
		}
		if metaGoOS.Valid {
			peer.Meta.GoOS = metaGoOS.String
		}
		if metaOSVersion.Valid {
			peer.Meta.OSVersion = metaOSVersion.String
		}
		if metaKernelVersion.Valid {
			peer.Meta.KernelVersion = metaKernelVersion.String
		}
		if locationCountryCode.Valid {
			peer.Location.CountryCode = locationCountryCode.String
		}
		if locationCityName.Valid {
			peer.Location.CityName = locationCityName.String
		}
		if ip != nil {
			err := json.Unmarshal(ip, &peer.IP)
			if err != nil {
				return peer, err
			}
		}
		if ipv6 != nil {
			err := json.Unmarshal(ipv6, &peer.IPv6)
			if err != nil {
				return peer, err
			}
		}
		if locationConnectionIp != nil {
			err := json.Unmarshal(locationConnectionIp, &peer.Location.ConnectionIP)
			if err != nil {
				return peer, err
			}
		}
		if metaFiles != nil {
			err := json.Unmarshal(metaFiles, &peer.Meta.Files)
			if err != nil {
				return peer, err
			}
		}
		if metaCapabilities != nil {
			err := json.Unmarshal(metaCapabilities, &peer.Meta.Capabilities)
			if err != nil {
				return peer, err
			}
		}
		if metaFlags != nil {
			err := json.Unmarshal(metaFlags, &peer.Meta.Flags)
			if err != nil {
				return peer, err
			}
		}
		if metaNetworkAddresses != nil {
			err := json.Unmarshal(metaNetworkAddresses, &peer.Meta.NetworkAddresses)
			if err != nil {
				return peer, err
			}
		}
		return peer, nil
	})

	return peers, err
}
