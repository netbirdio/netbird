package networkmap_pgsql

import (
	"context"

	"github.com/jackc/pgx/v5"
	networkmapdb "github.com/netbirdio/netbird/management/internals/network_map_db"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

const (
	peerColumns = `
	select id, key, ssh_key, dns_label, extra_dns_labels, user_id, ssh_enabled, login_expiration_enabled, last_login, ip, ipv6,
	peer_status_requires_approval, peer_status_connected, proxy_meta_embedded, proxy_meta_cluster,
	meta_wt_version, meta_go_os, meta_os_version, meta_kernel_version, meta_network_addresses, meta_files, meta_certificates, meta_capabilities, meta_flags, meta_sync_message_version,
	location_country_code, location_city_name, location_connection_ip
	from peers
	`

	GetPeersQuery = peerColumns + `where account_id = $1`

	GetPeersByIDsQuery = peerColumns + `where account_id = $1 and id = any($2) and not coalesce(proxy_meta_embedded, false)`

	GetProxyPeersQuery = peerColumns + `where account_id = $1 and proxy_meta_embedded`

	GetPeerVersionsQuery = `select distinct coalesce(meta_wt_version, '') from peers where account_id = $1`
)

func (pgc *PgStoreConn) GetPeers(ctx context.Context, accountId string) ([]nmdata.Peer, map[string][]*nmdata.Peer, error) {
	rows, err := pgc.Conn.Query(ctx, GetPeersQuery, accountId)
	if err != nil {
		return nil, nil, err
	}
	return collectPeers(rows)
}

func collectPeers(rows pgx.Rows) ([]nmdata.Peer, map[string][]*nmdata.Peer, error) {
	peers, err := pgx.CollectRows(rows, pgx.RowToStructByName[networkmapdb.Peer])
	if err != nil {
		return nil, nil, err
	}

	return networkmapdb.ConvertToNmdataPeers(peers)
}

func (pgc *PgStoreConn) GetPeersByIDs(ctx context.Context, accountId string, peerIDs []string) ([]nmdata.Peer, error) {
	rows, err := pgc.Conn.Query(ctx, GetPeersByIDsQuery, accountId, peerIDs)
	if err != nil {
		return nil, err
	}
	peers, _, err := collectPeers(rows)
	return peers, err
}

func (pgc *PgStoreConn) GetProxyPeers(ctx context.Context, accountId string) ([]nmdata.Peer, error) {
	rows, err := pgc.Conn.Query(ctx, GetProxyPeersQuery, accountId)
	if err != nil {
		return nil, err
	}
	peers, _, err := collectPeers(rows)
	return peers, err
}

func (pgc *PgStoreConn) GetPeerVersions(ctx context.Context, accountId string) ([]string, error) {
	rows, err := pgc.Conn.Query(ctx, GetPeerVersionsQuery, accountId)
	if err != nil {
		return nil, err
	}
	return collectPeerVersions(rows)
}

func collectPeerVersions(rows pgx.Rows) ([]string, error) {
	return pgx.CollectRows(rows, pgx.RowTo[string])
}
