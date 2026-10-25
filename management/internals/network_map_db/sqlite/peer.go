package networkmap_sqlite

import (
	"context"
	"encoding/json"

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

	GetPeersQuery = peerColumns + `where account_id = ?`

	GetPeersByIDsQuery = peerColumns + `where account_id = ? and id in (select value from json_each(?)) and not coalesce(proxy_meta_embedded, false)`

	GetProxyPeersQuery = peerColumns + `where account_id = ? and proxy_meta_embedded`

	GetPeerVersionsQuery = `select distinct coalesce(meta_wt_version, '') from peers where account_id = ?`
)

func (sc *SqliteStoreConn) GetPeers(ctx context.Context, accountId string) ([]nmdata.Peer, map[string][]*nmdata.Peer, error) {
	rows, err := sc.Conn.QueryContext(ctx, GetPeersQuery, accountId)
	if err != nil {
		return nil, nil, err
	}

	peers, err := CollectRowsForSqlite[networkmapdb.Peer](rows)
	if err != nil {
		return nil, nil, err
	}

	return networkmapdb.ConvertToNmdataPeers(peers)
}

func (sc *SqliteStoreConn) GetPeersByIDs(ctx context.Context, accountId string, peerIDs []string) ([]nmdata.Peer, error) {
	ids, err := json.Marshal(peerIDs)
	if err != nil {
		return nil, err
	}
	return sc.queryPeers(ctx, GetPeersByIDsQuery, accountId, string(ids))
}

func (sc *SqliteStoreConn) GetProxyPeers(ctx context.Context, accountId string) ([]nmdata.Peer, error) {
	return sc.queryPeers(ctx, GetProxyPeersQuery, accountId)
}

func (sc *SqliteStoreConn) GetPeerVersions(ctx context.Context, accountId string) ([]string, error) {
	rows, err := sc.Conn.QueryContext(ctx, GetPeerVersionsQuery, accountId)
	if err != nil {
		return nil, err
	}
	return collectStrings(rows)
}

func (sc *SqliteStoreConn) queryPeers(ctx context.Context, query string, args ...any) ([]nmdata.Peer, error) {
	rows, err := sc.Conn.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}

	peers, err := CollectRowsForSqlite[networkmapdb.Peer](rows)
	if err != nil {
		return nil, err
	}

	converted, _, err := networkmapdb.ConvertToNmdataPeers(peers)
	return converted, err
}
