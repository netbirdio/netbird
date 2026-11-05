package networkmap_pgsql

import (
	"context"

	"github.com/jackc/pgx/v5"
	networkmapdb "github.com/netbirdio/netbird/management/internals/network_map_db"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

const (
	GetPeersQuery = `
	select peers.id, key, ssh_key, dns_label, extra_dns_labels, user_id, ssh_enabled, login_expiration_enabled, last_login, ip, ipv6,
	peer_status_requires_approval, pc.last_seen as peer_last_seen, pc.session_started_at as peer_session_started_at, mi.last_seen as instance_last_seen, proxy_meta_embedded, proxy_meta_cluster,
	meta_wt_version, meta_go_os, meta_os_version, meta_kernel_version, meta_network_addresses, meta_files, meta_certificates, meta_capabilities, meta_flags, meta_sync_message_version,
	location_country_code, location_city_name, location_connection_ip
	from peers
	left join peer_connections pc on pc.peer_id = peers.id
	left join management_instances mi on mi.id = pc.instance_id
	where peers.account_id = $1
	`
)

func (pgc *PgStoreConn) GetPeers(ctx context.Context, accountId string) ([]nmdata.Peer, map[string][]*nmdata.Peer, error) {
	rows, err := pgc.Conn.Query(ctx, GetPeersQuery, accountId)
	if err != nil {
		return nil, nil, err
	}

	peers, err := pgx.CollectRows(rows, pgx.RowToStructByName[networkmapdb.Peer])
	if err != nil {
		return nil, nil, err
	}

	return networkmapdb.ConvertToNmdataPeers(peers)
}
