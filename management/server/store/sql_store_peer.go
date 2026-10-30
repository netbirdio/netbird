package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

func (s *SqlStore) SavePeer(ctx context.Context, accountID string, peer *nbpeer.Peer) error {
	// To maintain data integrity, we create a copy of the peer's to prevent unintended updates to other fields.
	peerCopy := peer.Copy()
	peerCopy.AccountID = accountID

	err := s.transaction(ctx, func(tx *gorm.DB) error {
		// check if peer exists before saving
		var peerID string
		result := tx.Model(&nbpeer.Peer{}).Select("id").Take(&peerID, accountAndIDQueryCondition, accountID, peer.ID)
		if result.Error != nil {
			if errors.Is(result.Error, gorm.ErrRecordNotFound) {
				return status.Errorf(status.NotFound, peerNotFoundFMT, peer.ID)
			}
			return result.Error
		}

		if peerID == "" {
			return status.Errorf(status.NotFound, peerNotFoundFMT, peer.ID)
		}

		result = tx.Model(&nbpeer.Peer{}).Where(accountAndIDQueryCondition, accountID, peer.ID).Save(peerCopy)
		if result.Error != nil {
			return status.Errorf(status.Internal, "failed to save peer to store: %v", result.Error)
		}

		return nil
	})
	if err != nil {
		return err
	}

	return nil
}

func (s *SqlStore) SavePeerStatus(ctx context.Context, accountID, peerID string, peerStatus nbpeer.PeerStatus) error {
	var peerCopy nbpeer.Peer
	peerCopy.Status = &peerStatus

	fieldsToUpdate := []string{"peer_status_login_expired", "peer_status_requires_approval"}
	result := s.db.Model(&nbpeer.Peer{}).
		Select(fieldsToUpdate).
		Where(accountAndIDQueryCondition, accountID, peerID).
		Updates(&peerCopy)
	if result.Error != nil {
		return status.Errorf(status.Internal, "failed to save peer status to store: %v", result.Error)
	}

	if result.RowsAffected == 0 {
		return status.Errorf(status.NotFound, peerNotFoundFMT, peerID)
	}

	return nil
}

// ApproveAccountPeers marks all peers that currently require approval in the given account as approved.
func (s *SqlStore) ApproveAccountPeers(ctx context.Context, accountID string) (int, error) {
	result := s.db.Model(&nbpeer.Peer{}).
		Where("account_id = ? AND peer_status_requires_approval = ?", accountID, true).
		Update("peer_status_requires_approval", false)
	if result.Error != nil {
		return 0, status.Errorf(status.Internal, "failed to approve pending account peers: %v", result.Error)
	}

	return int(result.RowsAffected), nil
}

// RefreshPeerLastSeen stamps the LastSeen of the peer's connection record with the
// database clock. Which instance holds the connection and its session are left
// untouched.
//
// LastSeen comes from the database clock: a Go-side timestamp is taken before the
// write and can land after a connect that used CURRENT_TIMESTAMP, dragging the
// column backwards.
//
// staleBefore carries the caller's throttle into the same statement, so
// concurrent requests for one peer collapse into a single write instead of
// each racing on its own stale read. The column is nullable, and NULL loses
// every comparison, hence the explicit branch for a peer never seen.
func (s *SqlStore) RefreshPeerLastSeen(ctx context.Context, accountID, peerID string, staleBefore time.Time) (bool, error) {
	result := s.db.WithContext(ctx).Exec(
		`UPDATE peer_connections SET last_seen = CURRENT_TIMESTAMP
		WHERE account_id = ? AND peer_id = ? AND (last_seen IS NULL OR last_seen < ?)`,
		accountID, peerID, staleBefore,
	)
	if result.Error != nil {
		return false, status.Errorf(status.Internal, "refresh peer last seen: %v", result.Error)
	}

	return result.RowsAffected > 0, nil
}

func (s *SqlStore) getPeers(ctx context.Context, accountID string) ([]nbpeer.Peer, error) {
	const query = `SELECT peers.id, peers.account_id, peers.key, peers.ip, peers.name, peers.dns_label, peers.user_id, peers.ssh_key,
	peers.ssh_enabled, peers.login_expiration_enabled, peers.inactivity_expiration_enabled, peers.last_login, peers.created_at,
	peers.ephemeral, peers.extra_dns_labels, peers.allow_extra_dns_labels, peers.meta_hostname, peers.meta_go_os, peers.meta_kernel,
	peers.meta_core, peers.meta_platform, peers.meta_os, peers.meta_os_version, peers.meta_wt_version, peers.meta_ui_version,
	peers.meta_kernel_version, peers.meta_network_addresses, peers.meta_system_serial_number, peers.meta_system_product_name,
	peers.meta_system_manufacturer, peers.meta_environment, peers.meta_flags, peers.meta_files, peers.meta_certificates,
	peers.meta_capabilities, pc.last_seen, pc.session_started_at, mi.last_seen, peers.peer_status_login_expired,
	peers.peer_status_requires_approval, peers.location_connection_ip, peers.location_country_code, peers.location_city_name,
	peers.location_geo_name_id, peers.proxy_meta_embedded, peers.proxy_meta_cluster, peers.ipv6, peers.meta_sync_message_version
	FROM peers
	LEFT JOIN peer_connections pc ON pc.peer_id = peers.id
	LEFT JOIN management_instances mi ON mi.id = pc.instance_id
	WHERE peers.account_id = $1`
	rows, err := s.pgxPool().Query(ctx, query, accountID)
	if err != nil {
		return nil, err
	}

	peers, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (nbpeer.Peer, error) {
		var p nbpeer.Peer
		p.Status = &nbpeer.PeerStatus{}
		var (
			lastLogin, createdAt                                                                            sql.NullTime
			sshEnabled, loginExpirationEnabled, inactivityExpirationEnabled, ephemeral, allowExtraDNSLabels sql.NullBool
			peerLastSeen                                                                                    sql.NullTime
			sessionStartedAt                                                                                sql.NullInt64
			instanceLastSeen                                                                                sql.NullTime
			peerStatusLoginExpired, peerStatusRequiresApproval, proxyEmbedded                               sql.NullBool
			ip, extraDNS, netAddr, env, flags, files, certificates, capabilities, connIP, ipv6              []byte
			metaHostname, metaGoOS, metaKernel, metaCore, metaPlatform                                      sql.NullString
			metaOS, metaOSVersion, metaWtVersion, metaUIVersion, metaKernelVersion                          sql.NullString
			metaSystemSerialNumber, metaSystemProductName, metaSystemManufacturer                           sql.NullString
			locationCountryCode, locationCityName, proxyCluster                                             sql.NullString
			locationGeoNameID                                                                               sql.NullInt64
			metaSyncMessageVersion                                                                          sql.NullInt32
		)

		err := row.Scan(&p.ID, &p.AccountID, &p.Key, &ip, &p.Name, &p.DNSLabel, &p.UserID, &p.SSHKey, &sshEnabled,
			&loginExpirationEnabled, &inactivityExpirationEnabled, &lastLogin, &createdAt, &ephemeral, &extraDNS,
			&allowExtraDNSLabels, &metaHostname, &metaGoOS, &metaKernel, &metaCore, &metaPlatform,
			&metaOS, &metaOSVersion, &metaWtVersion, &metaUIVersion, &metaKernelVersion, &netAddr,
			&metaSystemSerialNumber, &metaSystemProductName, &metaSystemManufacturer, &env, &flags, &files, &certificates, &capabilities,
			&peerLastSeen, &sessionStartedAt, &instanceLastSeen, &peerStatusLoginExpired,
			&peerStatusRequiresApproval, &connIP, &locationCountryCode, &locationCityName, &locationGeoNameID,
			&proxyEmbedded, &proxyCluster, &ipv6, &metaSyncMessageVersion)

		if err == nil {
			if lastLogin.Valid {
				p.LastLogin = &lastLogin.Time
			}
			if createdAt.Valid {
				p.CreatedAt = createdAt.Time
			}
			if sshEnabled.Valid {
				p.SSHEnabled = sshEnabled.Bool
			}
			if loginExpirationEnabled.Valid {
				p.LoginExpirationEnabled = loginExpirationEnabled.Bool
			}
			if inactivityExpirationEnabled.Valid {
				p.InactivityExpirationEnabled = inactivityExpirationEnabled.Bool
			}
			if ephemeral.Valid {
				p.Ephemeral = ephemeral.Bool
			}
			if allowExtraDNSLabels.Valid {
				p.AllowExtraDNSLabels = allowExtraDNSLabels.Bool
			}
			p.Status.ApplyConnection(sessionStartedAt, peerLastSeen, instanceLastSeen)
			if peerStatusLoginExpired.Valid {
				p.Status.LoginExpired = peerStatusLoginExpired.Bool
			}
			if peerStatusRequiresApproval.Valid {
				p.Status.RequiresApproval = peerStatusRequiresApproval.Bool
			}
			if metaHostname.Valid {
				p.Meta.Hostname = metaHostname.String
			}
			if metaGoOS.Valid {
				p.Meta.GoOS = metaGoOS.String
			}
			if metaKernel.Valid {
				p.Meta.Kernel = metaKernel.String
			}
			if metaCore.Valid {
				p.Meta.Core = metaCore.String
			}
			if metaPlatform.Valid {
				p.Meta.Platform = metaPlatform.String
			}
			if metaOS.Valid {
				p.Meta.OS = metaOS.String
			}
			if metaOSVersion.Valid {
				p.Meta.OSVersion = metaOSVersion.String
			}
			if metaWtVersion.Valid {
				p.Meta.WtVersion = metaWtVersion.String
			}
			if metaUIVersion.Valid {
				p.Meta.UIVersion = metaUIVersion.String
			}
			if metaKernelVersion.Valid {
				p.Meta.KernelVersion = metaKernelVersion.String
			}
			if metaSystemSerialNumber.Valid {
				p.Meta.SystemSerialNumber = metaSystemSerialNumber.String
			}
			if metaSystemProductName.Valid {
				p.Meta.SystemProductName = metaSystemProductName.String
			}
			if metaSystemManufacturer.Valid {
				p.Meta.SystemManufacturer = metaSystemManufacturer.String
			}
			if locationCountryCode.Valid {
				p.Location.CountryCode = locationCountryCode.String
			}
			if locationCityName.Valid {
				p.Location.CityName = locationCityName.String
			}
			if locationGeoNameID.Valid {
				p.Location.GeoNameID = uint(locationGeoNameID.Int64)
			}
			if proxyEmbedded.Valid {
				p.ProxyMeta.Embedded = proxyEmbedded.Bool
			}
			if proxyCluster.Valid {
				p.ProxyMeta.Cluster = proxyCluster.String
			}
			if ip != nil {
				_ = json.Unmarshal(ip, &p.IP)
			}
			if ipv6 != nil {
				_ = json.Unmarshal(ipv6, &p.IPv6)
			}
			if extraDNS != nil {
				_ = json.Unmarshal(extraDNS, &p.ExtraDNSLabels)
			}
			if netAddr != nil {
				_ = json.Unmarshal(netAddr, &p.Meta.NetworkAddresses)
			}
			if env != nil {
				_ = json.Unmarshal(env, &p.Meta.Environment)
			}
			if flags != nil {
				_ = json.Unmarshal(flags, &p.Meta.Flags)
			}
			if files != nil {
				_ = json.Unmarshal(files, &p.Meta.Files)
			}
			if certificates != nil {
				_ = json.Unmarshal(certificates, &p.Meta.Certificates)
			}
			if capabilities != nil {
				_ = json.Unmarshal(capabilities, &p.Meta.Capabilities)
			}
			if connIP != nil {
				_ = json.Unmarshal(connIP, &p.Location.ConnectionIP)
			}
			if metaSyncMessageVersion.Valid {
				p.Meta.SyncMessageVersion = int(metaSyncMessageVersion.Int32)
			}
		}
		return p, err
	})
	if err != nil {
		return nil, err
	}
	return peers, nil
}

func (s *SqlStore) GetAccountByPeerID(ctx context.Context, peerID string) (*types.Account, error) {
	var peer nbpeer.Peer
	result := s.db.Select("account_id").Take(&peer, idQueryCondition, peerID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(status.NotFound, "account not found: index lookup failed")
		}
		return nil, status.NewGetAccountFromStoreError(result.Error)
	}

	if peer.AccountID == "" {
		return nil, status.Errorf(status.NotFound, "account not found: index lookup failed")
	}

	return s.GetAccount(ctx, peer.AccountID)
}

func (s *SqlStore) GetAccountByPeerPubKey(ctx context.Context, peerKey string) (*types.Account, error) {
	var peer nbpeer.Peer
	result := s.db.Select("account_id").Take(&peer, keyQueryCondition, peerKey)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(status.NotFound, "account not found: index lookup failed")
		}
		return nil, status.NewGetAccountFromStoreError(result.Error)
	}

	if peer.AccountID == "" {
		return nil, status.Errorf(status.NotFound, "account not found: index lookup failed")
	}

	return s.GetAccount(ctx, peer.AccountID)
}

func (s *SqlStore) GetAccountIDByPeerPubKey(ctx context.Context, peerKey string) (string, error) {
	var peer nbpeer.Peer
	var accountID string
	result := s.db.Model(&peer).Select("account_id").Where(keyQueryCondition, peerKey).Take(&accountID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return "", status.Errorf(status.NotFound, "account not found: index lookup failed")
		}
		return "", status.NewGetAccountFromStoreError(result.Error)
	}

	return accountID, nil
}

func (s *SqlStore) GetAccountIDByPeerID(ctx context.Context, lockStrength LockingStrength, peerID string) (string, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var accountID string
	result := tx.Model(&nbpeer.Peer{}).
		Select("account_id").Where(idQueryCondition, peerID).Take(&accountID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return "", status.Errorf(status.NotFound, "peer %s account not found", peerID)
		}
		return "", status.NewGetAccountFromStoreError(result.Error)
	}

	return accountID, nil
}

func (s *SqlStore) GetTakenIPs(ctx context.Context, lockStrength LockingStrength, accountID string) ([]netip.Addr, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var ipJSONStrings []string

	result := tx.Model(&nbpeer.Peer{}).
		Where("account_id = ?", accountID).
		Pluck("ip", &ipJSONStrings)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(status.NotFound, "no peers found for the account")
		}
		return nil, status.Errorf(status.Internal, "issue getting IPs from store: %s", result.Error)
	}

	ips := make([]netip.Addr, len(ipJSONStrings))
	for i, ipJSON := range ipJSONStrings {
		var ip netip.Addr
		if err := json.Unmarshal([]byte(ipJSON), &ip); err != nil {
			return nil, status.Errorf(status.Internal, "issue parsing IP JSON from store")
		}
		ips[i] = ip.Unmap()
	}

	return ips, nil
}

func (s *SqlStore) GetPeerLabelsInAccount(ctx context.Context, lockStrength LockingStrength, accountID string, dnsLabel string) ([]string, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var labels []string
	result := tx.Model(&nbpeer.Peer{}).
		Where("account_id = ? AND dns_label LIKE ?", accountID, dnsLabel+"%").
		Pluck("dns_label", &labels)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(status.NotFound, "no peers found for the account")
		}
		log.WithContext(ctx).Errorf("error when getting dns labels from the store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "issue getting dns labels from store: %s", result.Error)
	}

	return labels, nil
}

func (s *SqlStore) GetPeerByPeerPubKey(ctx context.Context, lockStrength LockingStrength, peerKey string) (*nbpeer.Peer, error) {
	peer, err := s.takePeerWithConnection(ctx, lockStrength, "peers.key = ?", peerKey)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.NewPeerNotFoundError(peerKey)
		}
		return nil, status.Errorf(status.Internal, "issue getting peer from store: %s", err)
	}

	return peer, nil
}

func (s *SqlStore) GetAccountPeers(ctx context.Context, lockStrength LockingStrength, accountID, nameFilter, ipFilter, macFilter string) ([]*nbpeer.Peer, error) {
	var peers []*nbpeer.Peer
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}
	query := tx.Where(accountIDCondition, accountID)

	if nameFilter != "" {
		query = query.Where("name LIKE ?", "%"+nameFilter+"%")
	}
	if ipFilter != "" {
		query = query.Where("ip LIKE ? OR ipv6 LIKE ?", "%"+ipFilter+"%", "%"+ipFilter+"%")
	}
	// MAC addresses live in the JSON-serialized meta_network_addresses column,
	// so we match the raw JSON text rather than a dedicated column.
	if macFilter != "" {
		query = query.Where("meta_network_addresses LIKE ?", "%"+macFilter+"%")
	}
	if err := query.Find(&peers).Error; err != nil {
		log.WithContext(ctx).Errorf("failed to get peers from the store: %s", err)
		return nil, status.Errorf(status.Internal, "failed to get peers from store")
	}

	if err := s.attachPeerConnections(ctx, peers...); err != nil {
		log.WithContext(ctx).Errorf("failed to get peers from the store: %s", err)
		return nil, status.Errorf(status.Internal, "failed to get peers from store")
	}

	return peers, nil
}

// GetAccountPeers retrieves peers for an account.
func (s *SqlStore) GetAccountPeersPaginated(ctx context.Context, lockStrength LockingStrength, accountID string, pagination PaginationState, filters PeerFilters, sorting PeerSorting) ([]*nbpeer.Peer, int, error) {
	// main query
	var peers []*nbpeer.Peer
	{
		tx := s.db
		if lockStrength != LockingStrengthNone {
			tx = tx.Clauses(clause.Locking{Strength: string(lockStrength), Table: clause.Table{Name: "peers"}})
		}
		query := tx.Where("peers.account_id=?", accountID)
		query = query.Where("(peers.proxy_meta_embedded=false or peers.proxy_meta_embedded is null)")
		query = filters.AsConditions(query, s.conn.Engine())
		query = pagination.AsScope(query)
		query = sorting.AsOrderBy(ctx, query)

		if err := query.Find(&peers).Error; err != nil {
			log.WithContext(ctx).Errorf("failed to get peers from the store: %s", err)
			return nil, 0, status.Errorf(status.Internal, "failed to get peers from store")
		}
	}

	if err := s.attachPeerConnections(ctx, peers...); err != nil {
		log.WithContext(ctx).Errorf("failed to get peers from the store: %s", err)
		return nil, 0, status.Errorf(status.Internal, "failed to get peers from store")
	}

	// total number of records
	var peerCount int64
	{
		tx := s.db
		if lockStrength != LockingStrengthNone {
			tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
		}
		query := tx.Where("peers.account_id=?", accountID)
		query = query.Where("(peers.proxy_meta_embedded=false or peers.proxy_meta_embedded is null)")
		query = filters.AsConditions(query, s.conn.Engine())

		if err := query.Table("peers").Select("count(distinct(peers.id))").Count(&peerCount).Error; err != nil {
			log.WithContext(ctx).Errorf("failed to get total number of peers from the store: %s", err)
			return nil, 0, status.Errorf(status.Internal, "failed to get total number of peers from store")
		}
	}

	return peers, int(peerCount), nil
}

type PaginationState struct {
	Page     int
	PageSize int
}

func (p *PaginationState) AsScope(db *gorm.DB) *gorm.DB {
	// empty pagination state
	if p.PageSize == 0 {
		return db
	}
	offset := max(p.Page-1, 0) * p.PageSize
	return db.Offset(offset).Limit(p.PageSize)
}

type PeerFilters struct {
	UserId           string
	GroupIds         []string
	Connected        *bool
	ApprovalRequired *bool
	Os               []string
	IP               string
	MAC              string
	Hostname         string
	Name             string
	IsServer         *bool
	PeersIds         []string
}

func (f *PeerFilters) AsConditions(db *gorm.DB, engine types.Engine) *gorm.DB {
	if len(f.GroupIds) > 0 {
		db = db.Where("peers.id IN (SELECT group_peers.peer_id FROM group_peers WHERE group_peers.account_id = peers.account_id AND group_peers.group_id IN (?))", f.GroupIds)
	}
	if f.UserId != "" {
		db = db.Where("peers.user_id=?", f.UserId)
	}
	if f.Connected != nil {
		threshold, arg := staleThresholdFor(engine)
		exists := "EXISTS"
		if !*f.Connected {
			exists = "NOT EXISTS"
		}
		db = db.Where(exists+" (SELECT 1 FROM peer_connections pc JOIN management_instances mi ON mi.id = pc.instance_id WHERE pc.peer_id = peers.id AND mi.last_seen >= "+threshold+")", arg)
	}
	if f.ApprovalRequired != nil {
		db = db.Where("peer_status_requires_approval=?", *f.ApprovalRequired)
	}
	if len(f.Os) > 0 {
		db = db.Where("meta_go_os in (?)", f.Os)
	}
	if f.IP != "" {
		db = db.Where("ip like ? or lower(ipv6) like ?", fmt.Sprintf("%%%s%%", f.IP), fmt.Sprintf("%%%s%%", strings.ToLower(f.IP)))
	}
	if f.MAC != "" {
		db = db.Where("lower(meta_network_addresses) like ?", fmt.Sprintf("%%%s%%", strings.ToLower(f.MAC)))
	}
	if f.Hostname != "" {
		db = db.Where("lower(meta_hostname) like ?", fmt.Sprintf("%%%s%%", strings.ToLower(f.Hostname)))
	}
	if f.Name != "" {
		db = db.Where("lower(name) like ?", fmt.Sprintf("%%%s%%", strings.ToLower(f.Name)))
	}
	if f.IsServer != nil {
		if *f.IsServer {
			db = db.Where("(user_id='' or user_id is null)")
		} else {
			db = db.Where("user_id<>'' and user_id is not null")
		}
	}
	if len(f.PeersIds) > 0 {
		db = db.Where("peers.id in (?)", f.PeersIds)
	}

	return db
}

// effectiveLastSeenSQL orders peers by the later of their connection record's LastSeen and the
// LastSeen of the instance holding it, matching nbpeer.PeerStatus.ApplyConnection.
const effectiveLastSeenSQL = `CASE WHEN sort_mi.last_seen IS NOT NULL AND (sort_pc.last_seen IS NULL OR sort_mi.last_seen > sort_pc.last_seen) THEN sort_mi.last_seen ELSE sort_pc.last_seen END`

type PeerSortByField int

const (
	PeerSortByName PeerSortByField = iota
	PeerSortByLastSeen
	PeerSortByVersion
)

type OrderBy int

const (
	AscOrderBy OrderBy = iota
	DescOrderBy
)

type PeerSortingKey struct {
	Field PeerSortByField
	Order OrderBy
}

type PeerSorting struct {
	Fields []PeerSortingKey
}

func (s *PeerSorting) AsOrderBy(ctx context.Context, db *gorm.DB) *gorm.DB {
	order := make([]clause.OrderByColumn, 0)
	joinedInstances := false

	for _, key := range s.Fields {
		switch key.Field {
		case PeerSortByName:
			order = append(order, clause.OrderByColumn{Column: clause.Column{Name: "peers.name"}, Desc: key.Order == DescOrderBy})
		case PeerSortByLastSeen:
			if !joinedInstances {
				db = db.Joins("LEFT JOIN peer_connections sort_pc ON sort_pc.peer_id = peers.id").
					Joins("LEFT JOIN management_instances sort_mi ON sort_mi.id = sort_pc.instance_id")
				joinedInstances = true
			}
			order = append(order, clause.OrderByColumn{Column: clause.Column{Name: effectiveLastSeenSQL, Raw: true}, Desc: key.Order == DescOrderBy})
		case PeerSortByVersion:
			order = append(order, clause.OrderByColumn{Column: clause.Column{Name: "meta_wt_version"}, Desc: key.Order == DescOrderBy})
		default:
			log.WithContext(ctx).Warnf("invalid order by column '%v', skipping", key.Field)
		}
	}

	// always order/break ties by id asc order
	order = append(order, clause.OrderByColumn{Column: clause.Column{Name: "peers.id"}, Desc: false})
	return db.Order(clause.OrderBy{Columns: order})
}

// GetUserPeers retrieves peers for a user.
func (s *SqlStore) GetUserPeers(ctx context.Context, lockStrength LockingStrength, accountID, userID string) ([]*nbpeer.Peer, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var peers []*nbpeer.Peer

	// Exclude peers added via setup keys, as they are not user-specific and have an empty user_id.
	if userID == "" {
		return peers, nil
	}

	result := tx.
		Find(&peers, "account_id = ? AND user_id = ?", accountID, userID)
	if err := result.Error; err != nil {
		log.WithContext(ctx).Errorf("failed to get peers from the store: %s", err)
		return nil, status.Errorf(status.Internal, "failed to get peers from store")
	}

	if err := s.attachPeerConnections(ctx, peers...); err != nil {
		log.WithContext(ctx).Errorf("failed to get peers from the store: %s", err)
		return nil, status.Errorf(status.Internal, "failed to get peers from store")
	}

	return peers, nil
}

// AddPeerToAccount stores a new peer together with its connection record.
func (s *SqlStore) AddPeerToAccount(ctx context.Context, peer *nbpeer.Peer) error {
	err := s.transaction(ctx, func(tx *gorm.DB) error {
		if err := tx.Create(peer).Error; err != nil {
			return err
		}
		return createPeerConnections(tx, peer)
	})
	if err != nil {
		return status.Errorf(status.Internal, "issue adding peer to account: %s", err)
	}

	return nil
}

// GetPeerByID retrieves a peer by its ID and account ID.
func (s *SqlStore) GetPeerByID(ctx context.Context, lockStrength LockingStrength, accountID, peerID string) (*nbpeer.Peer, error) {
	peer, err := s.takePeerWithConnection(ctx, lockStrength, "peers.account_id = ? AND peers.id = ?", accountID, peerID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.NewPeerNotFoundError(peerID)
		}
		log.WithContext(ctx).Errorf("failed to get peer from the store: %s", err)
		return nil, status.Errorf(status.Internal, "failed to get peer from store")
	}

	return peer, nil
}

// GetPeersByIDs retrieves peers by their IDs and account ID.
func (s *SqlStore) GetPeersByIDs(ctx context.Context, lockStrength LockingStrength, accountID string, peerIDs []string) (map[string]*nbpeer.Peer, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var peers []*nbpeer.Peer
	result := tx.Find(&peers, accountAndIDsQueryCondition, accountID, peerIDs)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get peers by ID's from the store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get peers by ID's from the store")
	}

	if err := s.attachPeerConnections(ctx, peers...); err != nil {
		log.WithContext(ctx).Errorf("failed to get peers by ID's from the store: %s", err)
		return nil, status.Errorf(status.Internal, "failed to get peers by ID's from the store")
	}

	peersMap := make(map[string]*nbpeer.Peer)
	for _, peer := range peers {
		peersMap[peer.ID] = peer
	}

	return peersMap, nil
}

// GetAccountPeersWithExpiration retrieves a list of peers that have login expiration enabled and added by a user.
func (s *SqlStore) GetAccountPeersWithExpiration(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*nbpeer.Peer, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var peers []*nbpeer.Peer
	result := tx.
		Where("login_expiration_enabled = ? AND peer_status_login_expired != ? AND user_id IS NOT NULL AND user_id != ''", true, true).
		Find(&peers, accountIDCondition, accountID)
	if err := result.Error; err != nil {
		log.WithContext(ctx).Errorf("failed to get peers with expiration from the store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get peers with expiration from store")
	}

	if err := s.attachPeerConnections(ctx, peers...); err != nil {
		log.WithContext(ctx).Errorf("failed to get peers with expiration from the store: %s", err)
		return nil, status.Errorf(status.Internal, "failed to get peers with expiration from store")
	}

	return peers, nil
}

// GetAccountPeersWithInactivity retrieves a list of peers that have login expiration enabled and added by a user.
func (s *SqlStore) GetAccountPeersWithInactivity(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*nbpeer.Peer, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var peers []*nbpeer.Peer
	result := tx.
		Where("inactivity_expiration_enabled = ? AND user_id IS NOT NULL AND user_id != ''", true).
		Find(&peers, accountIDCondition, accountID)
	if err := result.Error; err != nil {
		log.WithContext(ctx).Errorf("failed to get peers with inactivity from the store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get peers with inactivity from store")
	}

	if err := s.attachPeerConnections(ctx, peers...); err != nil {
		log.WithContext(ctx).Errorf("failed to get peers with inactivity from the store: %s", err)
		return nil, status.Errorf(status.Internal, "failed to get peers with inactivity from store")
	}

	return peers, nil
}

// GetAllEphemeralPeers retrieves all peers with Ephemeral set to true across all accounts, optimized for batch processing.
func (s *SqlStore) GetAllEphemeralPeers(ctx context.Context, lockStrength LockingStrength) ([]*nbpeer.Peer, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var allEphemeralPeers, batchPeers []*nbpeer.Peer
	result := tx.
		Where("ephemeral = ?", true).
		FindInBatches(&batchPeers, 1000, func(tx *gorm.DB, batch int) error {
			allEphemeralPeers = append(allEphemeralPeers, batchPeers...)
			return nil
		})

	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to retrieve ephemeral peers: %s", result.Error)
		return nil, fmt.Errorf("failed to retrieve ephemeral peers")
	}

	if err := s.attachPeerConnections(ctx, allEphemeralPeers...); err != nil {
		log.WithContext(ctx).Errorf("failed to retrieve ephemeral peers: %s", err)
		return nil, fmt.Errorf("failed to retrieve ephemeral peers")
	}

	return allEphemeralPeers, nil
}

// DeletePeer removes a peer from the store.
func (s *SqlStore) DeletePeer(ctx context.Context, accountID string, peerID string) error {
	var deleted int64
	err := s.transaction(ctx, func(tx *gorm.DB) error {
		result := tx.Delete(&nbpeer.Peer{}, accountAndIDQueryCondition, accountID, peerID)
		if result.Error != nil {
			return result.Error
		}
		deleted = result.RowsAffected
		if deleted == 0 {
			return nil
		}
		return tx.Delete(&nbpeer.Connection{}, accountAndPeerIDQueryCondition, accountID, peerID).Error
	})
	if err != nil {
		log.WithContext(ctx).Errorf("failed to delete peer from the store: %s", err)
		return status.Errorf(status.Internal, "failed to delete peer from store")
	}

	if deleted == 0 {
		return status.NewPeerNotFoundError(peerID)
	}

	return nil
}

func (s *SqlStore) GetPeerByIP(ctx context.Context, lockStrength LockingStrength, accountID string, ip net.IP) (*nbpeer.Peer, error) {
	column := "peers.ip"
	if ip.To4() == nil {
		column = "peers.ipv6"
	}
	jsonValue := fmt.Sprintf(`"%s"`, ip.String())

	peer, err := s.takePeerWithConnection(ctx, lockStrength, fmt.Sprintf("peers.account_id = ? AND %s = ?", column), accountID, jsonValue)
	if err != nil {
		// A tunnel-IP miss is an expected outcome (e.g. the proxy's
		// ValidateTunnelPeer probing an address that isn't in the
		// account roster); surface it as NotFound so callers can tell
		// it apart from a real store failure.
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(status.NotFound, "peer with ip %s not found", ip.String())
		}
		log.WithContext(ctx).Errorf("failed to get peer from the store: %s", err)
		return nil, status.Errorf(status.Internal, "failed to get peer from store")
	}

	return peer, nil
}

func (s *SqlStore) GetPeerIdByLabel(ctx context.Context, lockStrength LockingStrength, accountID string, hostname string) (string, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var peerID string
	result := tx.Model(&nbpeer.Peer{}).
		Select("id").
		// Where(" = ?", hostname).
		Where("account_id = ? AND dns_label = ?", accountID, hostname).
		Limit(1).
		Scan(&peerID)
	if result.Error != nil {
		return "", result.Error
	}

	if peerID == "" {
		return "", gorm.ErrRecordNotFound
	}

	return peerID, nil
}

// GetEmbeddedProxyPeerIDsByCluster returns peer IDs of all embedded proxy peers
// in the account, grouped by their ProxyCluster. The map is nil when no embedded
// proxy peers exist.
func (s *SqlStore) GetEmbeddedProxyPeerIDsByCluster(ctx context.Context, accountID string) (map[string][]string, error) {
	type row struct {
		ID      string
		Cluster string
	}
	var rows []row
	result := s.db.Model(&nbpeer.Peer{}).
		Select("id, proxy_meta_cluster AS cluster").
		Where("account_id = ? AND proxy_meta_embedded = ?", accountID, true).
		Scan(&rows)
	if result.Error != nil {
		return nil, status.Errorf(status.Internal, "failed to get embedded proxy peers: %s", result.Error)
	}

	out := make(map[string][]string, len(rows))
	for _, r := range rows {
		out[r.Cluster] = append(out[r.Cluster], r.ID)
	}
	return out, nil
}

func (s *SqlStore) GetUserIDByPeerKey(ctx context.Context, lockStrength LockingStrength, peerKey string) (string, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var userID string
	result := tx.Model(&nbpeer.Peer{}).
		Select("user_id").
		Take(&userID, keyQueryCondition, peerKey)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return "", status.Errorf(status.NotFound, "peer not found: index lookup failed")
		}
		return "", status.Errorf(status.Internal, "failed to get user ID by peer key")
	}

	return userID, nil
}

func (s *SqlStore) GetPeerIDByKey(ctx context.Context, lockStrength LockingStrength, key string) (string, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var peerID string
	result := tx.Model(&nbpeer.Peer{}).
		Select("id").
		Where(keyQueryCondition, key).
		Limit(1).
		Scan(&peerID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get peer ID by key: %s", result.Error)
		return "", status.Errorf(status.Internal, "failed to get peer ID by key")
	}

	return peerID, nil
}
