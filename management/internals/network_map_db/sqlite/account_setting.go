package networkmap_sqlite

import (
	"context"
	"database/sql"
	"reflect"

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

func (sc *SqliteStoreConn) GetAccountSettings(ctx context.Context, accountId string) (nmdata.AccountSettingsInfo, error) {
	rows, err := sc.Conn.QueryContext(ctx, GetAccountSettingsQuery, accountId)
	if err != nil {
		return nmdata.AccountSettingsInfo{}, err
	}

	a, err := networkmapdb.CollectOneRowForSqlite[account](rows)

	settingsInfo := nmdata.AccountSettingsInfo{}
	err = networkmapdb.FromSqlTypesToSharedTypes(reflect.ValueOf(&a), reflect.ValueOf(&settingsInfo))
	if err != nil {
		return nmdata.AccountSettingsInfo{}, err
	}

	return settingsInfo, nil
}

type account struct {
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
