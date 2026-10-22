package networkmap_pgsql

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	log "github.com/sirupsen/logrus"

	networkmapdb "github.com/netbirdio/netbird/management/internals/network_map_db"
)

const beginReadOnlyQuery = "begin read only isolation level repeatable read"

// LoadAccount reads the account's network-map rows over one connection in a
// read-only repeatable-read transaction, pipelining the queries of each step
// into a single round trip: one round trip without selectPeers, two with it,
// the second reading the selected peers and the client versions of all peers.
func (p *PgStore) LoadAccount(ctx context.Context, accountID string, selectPeers networkmapdb.PeerSelector) (*networkmapdb.AccountRows, error) {
	conn, err := p.Pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire connection: %w", err)
	}
	defer conn.Release()
	p.useLocation(conn.Conn())

	rows := &networkmapdb.AccountRows{}
	batch := &pgx.Batch{}
	batch.Queue(beginReadOnlyQuery)
	queueAccountRows(batch, accountID, rows)

	if selectPeers == nil {
		queuePeers(batch, rows, "peers", GetPeersQuery, accountID)
		batch.Queue("commit")
		if err := sendBatch(ctx, conn, batch); err != nil {
			return nil, err
		}
		return rows, nil
	}

	queuePeers(batch, rows, "proxy peers", GetProxyPeersQuery, accountID)
	if err := sendBatch(ctx, conn, batch); err != nil {
		return nil, err
	}

	peerIDs, all, err := selectPeers(rows)
	if err != nil {
		rollback(ctx, conn)
		return nil, err
	}

	batch = &pgx.Batch{}
	switch {
	case all:
		rows.Peers = nil
		queuePeers(batch, rows, "peers", GetPeersQuery, accountID)
	default:
		queuePeers(batch, rows, "peers by id", GetPeersByIDsQuery, accountID, peerIDs)
		queueRows(batch, "peer versions", func(r pgx.Rows) (err error) {
			rows.PeerVersions, err = collectPeerVersions(r)
			return err
		}, GetPeerVersionsQuery, accountID)
	}
	batch.Queue("commit")
	if err := sendBatch(ctx, conn, batch); err != nil {
		return nil, err
	}
	return rows, nil
}

// queueAccountRows queues the reads of every collection except the peer rows.
func queueAccountRows(batch *pgx.Batch, accountID string, rows *networkmapdb.AccountRows) {
	queueRows(batch, "account settings", func(r pgx.Rows) (err error) {
		rows.Settings, err = collectAccountSettings(r)
		return err
	}, GetAccountSettingsQuery, accountID)
	queueRows(batch, "applied zone candidates", func(r pgx.Rows) (err error) {
		rows.ZoneCandidates, err = collectAppliedZoneCandidates(r)
		return err
	}, GetAccountZonesQuery, accountID)
	queueRows(batch, "groups", func(r pgx.Rows) (err error) {
		rows.Groups, rows.ResourceToGroupIdx, err = collectGroups(r)
		return err
	}, GetGroupsQuery, accountID)
	queueRows(batch, "nameserver groups", func(r pgx.Rows) (err error) {
		rows.NameServerGroups, err = collectNameServerGroups(r)
		return err
	}, GetNameserversQuery, accountID)
	queueRows(batch, "network resources", func(r pgx.Rows) (err error) {
		rows.NetworkResources, err = collectNetworkResources(r)
		return err
	}, GetNetworkResourcesQuery, accountID)
	queueRows(batch, "network routers", func(r pgx.Rows) (err error) {
		rows.Routers, err = collectNetworkRouters(r)
		return err
	}, GetNetworkRouterQuery, accountID)
	queueRows(batch, "network", func(r pgx.Rows) (err error) {
		rows.Network, err = collectNetwork(r)
		return err
	}, GetNetworkQuery, accountID)
	queueRows(batch, "policies", func(r pgx.Rows) (err error) {
		rows.Policies, rows.PolicyToDestinationResourceIdx, rows.PolicyToDestinationGroupIdx, err = collectPolicies(r)
		return err
	}, GetPoliciesQuery, accountID)
	queueRows(batch, "posture checks", func(r pgx.Rows) (err error) {
		rows.PostureChecks, rows.PostureCheckXIDToPublicID, err = collectPostureChecks(r)
		return err
	}, GetPostureChecksQuery, accountID)
	queueRows(batch, "routes", func(r pgx.Rows) (err error) {
		rows.Routes, err = collectRoutes(r)
		return err
	}, GetRoutesQuery, accountID)
	queueRows(batch, "network xid to public id map", func(r pgx.Rows) (err error) {
		rows.NetworkXIDToPublicID, err = collectNetworkXIDToPublicIdMap(r)
		return err
	}, GetNetworksQuery, accountID)

	var users []user
	queueRows(batch, "allowed users", func(r pgx.Rows) (err error) {
		users, err = collectUsers(r)
		return err
	}, GetAllowedUserIdsQuery, accountID)
	queueRows(batch, "all group id", func(r pgx.Rows) error {
		allGroupIds, err := collectAllGroupIds(r)
		rows.AllowedUserIDs, rows.GroupIDToUserIDs = allowedUsers(users, allGroupIds)
		return err
	}, GetAllGroupIdQuery, accountID)

	queueRows(batch, "dns settings", func(r pgx.Rows) (err error) {
		rows.DNSSettings, err = collectDnsSettings(r)
		return err
	}, GetDnsSettingsQuery, accountID)
	queueRows(batch, "domains", func(r pgx.Rows) (err error) {
		rows.Domains, err = collectDomains(r)
		return err
	}, GetDomainsQuery, accountID)
	queueRows(batch, "proxy targeted domain resources", func(r pgx.Rows) (err error) {
		rows.ProxyTargetedDomainResourceIDs, err = collectProxyTargetedDomainResourceIDs(r)
		return err
	}, GetProxyTargetedDomainResourcesQuery, accountID)
}

// queuePeers queues a peer query whose rows are appended to rows.Peers.
func queuePeers(batch *pgx.Batch, rows *networkmapdb.AccountRows, what string, query string, args ...any) {
	queueRows(batch, what, func(r pgx.Rows) error {
		peers, _, err := collectPeers(r)
		rows.Peers = append(rows.Peers, peers...)
		return err
	}, query, args...)
}

func queueRows(batch *pgx.Batch, what string, collect func(pgx.Rows) error, query string, args ...any) {
	batch.Queue(query, args...).Query(func(r pgx.Rows) error {
		if err := collect(r); err != nil {
			return fmt.Errorf("get %s: %w", what, err)
		}
		return nil
	})
}

// sendBatch runs the batch. On failure it rolls back the transaction the batch
// may have left open, so the connection goes back to the pool reusable.
func sendBatch(ctx context.Context, conn *pgxpool.Conn, batch *pgx.Batch) error {
	if err := conn.SendBatch(ctx, batch).Close(); err != nil {
		rollback(ctx, conn)
		return err
	}
	return nil
}

func rollback(ctx context.Context, conn *pgxpool.Conn) {
	if _, err := conn.Exec(ctx, "rollback"); err != nil {
		log.WithContext(ctx).Debugf("rollback network map read transaction: %v", err)
	}
}
