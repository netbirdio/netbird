package networkmap_pgsql

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
	networkmapdb "github.com/netbirdio/netbird/management/internals/network_map_db"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

const (
	GetAccountSettingsQuery = `
	select settings_peer_login_expiration_enabled as peer_login_expiration_enabled,
	settings_peer_login_expiration as peer_login_expiration,
	settings_peer_inactivity_expiration_enabled as peer_inactivity_expiration_enabled,
	settings_peer_inactivity_expiration as peer_inactivity_expiration,
	settings_dns_domain as dns_domain,
	settings_ipv6_enabled_groups as ipv6_enabled_groups,
	settings_routing_peer_dns_resolution_enabled as routing_peer_dns_resolution_enabled,
	settings_lazy_connection_enabled as lazy_connection_enabled,
	settings_auto_update_version as auto_update_version,
	settings_auto_update_always as auto_update_always,
	settings_metrics_push_enabled as metrics_push_enabled
	from accounts
	where id=$1
	`
)

func (pgc *PgStoreConn) GetAccountSettings(ctx context.Context, accountId string) (nmdata.AccountSettingsInfo, error) {
	rows, err := pgc.Conn.Query(ctx, GetAccountSettingsQuery, accountId)
	if err != nil {
		return nmdata.AccountSettingsInfo{}, err
	}

	settings, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[networkmapdb.Account])
	if err != nil {
		return nmdata.AccountSettingsInfo{}, err
	}

	settingsInfo := nmdata.AccountSettingsInfo{
		PeerLoginExpirationEnabled:      settings.PeerLoginExpirationEnabled.Bool,
		PeerLoginExpiration:             time.Duration(settings.PeerLoginExpiration.Int64),
		PeerInactivityExpirationEnabled: settings.PeerInactivityExpirationEnabled.Bool,
		PeerInactivityExpiration:        time.Duration(settings.PeerInactivityExpiration.Int64),
		DNSDomain:                       settings.DNSDomain.String,
		RoutingPeerDNSResolutionEnabled: settings.RoutingPeerDNSResolutionEnabled.Bool,
		LazyConnectionEnabled:           settings.LazyConnectionEnabled.Bool,
		AutoUpdateVersion:               settings.AutoUpdateVersion.String,
		AutoUpdateAlways:                settings.AutoUpdateAlways.Bool,
		MetricsPushEnabled:              settings.MetricsPushEnabled.Bool,
	}
	if settings.IPv6EnabledGroups != nil {
		if err := json.Unmarshal(settings.IPv6EnabledGroups, &settingsInfo.IPv6EnabledGroups); err != nil {
			return nmdata.AccountSettingsInfo{}, err
		}
	}

	return settingsInfo, nil
}
