package networkmap_sqlite

import (
	"context"

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
	where account_id = ?
	`
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
