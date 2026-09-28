package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
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

	err := s.transaction(func(tx *gorm.DB) error {
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

	fieldsToUpdate := []string{
		"peer_status_last_seen", "peer_status_session_started_at",
		"peer_status_connected", "peer_status_login_expired",
		"peer_status_requires_approval",
	}
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

// MarkPeerConnectedIfNewerSession is an atomic optimistic-locked update.
// The peer is marked connected with the given session token only when
// the stored SessionStartedAt is strictly smaller than the incoming
// one — equivalently, when no newer stream has already taken ownership.
// The sentinel zero (set on peer creation or after a disconnect) counts
// as the smallest possible token. This is the write half of the
// fencing protocol described on PeerStatus.SessionStartedAt.
//
// The post-write side effects in the caller — geo lookup,
// schedulePeerLoginExpiration, checkAndSchedulePeerInactivityExpiration,
// OnPeersUpdated — all run AFTER this method returns and are deliberately
// outside the database write so they cannot extend the row-lock window.
//
// LastSeen is set to the database's clock (CURRENT_TIMESTAMP) at the
// moment the row is written. The caller never supplies LastSeen because
// the value would otherwise drift under lock contention — a Go-side
// time.Now() taken before the write can land minutes later than the
// actual UPDATE under load, which previously caused real ordering bugs.
func (s *SqlStore) MarkPeerConnectedIfNewerSession(ctx context.Context, accountID, peerID string, newSessionStartedAt int64) (bool, error) {
	result := s.db.WithContext(ctx).
		Model(&nbpeer.Peer{}).
		Where(accountAndIDQueryCondition, accountID, peerID).
		Where("peer_status_session_started_at < ?", newSessionStartedAt).
		Updates(map[string]any{
			"peer_status_connected":          true,
			"peer_status_last_seen":          gorm.Expr("CURRENT_TIMESTAMP"),
			"peer_status_session_started_at": newSessionStartedAt,
			"peer_status_login_expired":      false,
		})
	if result.Error != nil {
		return false, status.Errorf(status.Internal, "mark peer connected: %v", result.Error)
	}
	return result.RowsAffected > 0, nil
}

// MarkPeerDisconnectedIfSameSession is an atomic optimistic-locked update.
// The peer is marked disconnected only when the stored SessionStartedAt
// matches the incoming token — meaning the stream that owns the current
// session is the one ending. If a newer stream has already replaced the
// session, the update is skipped. LastSeen is set to CURRENT_TIMESTAMP at
// write time; see MarkPeerConnectedIfNewerSession for the rationale.
//
// A zero sessionStartedAt is rejected at the call site; the underlying
// WHERE on equality would otherwise match every never-connected peer.
func (s *SqlStore) MarkPeerDisconnectedIfSameSession(ctx context.Context, accountID, peerID string, sessionStartedAt int64) (bool, error) {
	if sessionStartedAt == 0 {
		return false, nil
	}
	result := s.db.WithContext(ctx).
		Model(&nbpeer.Peer{}).
		Where(accountAndIDQueryCondition, accountID, peerID).
		Where("peer_status_session_started_at = ?", sessionStartedAt).
		Updates(map[string]any{
			"peer_status_connected":          false,
			"peer_status_last_seen":          gorm.Expr("CURRENT_TIMESTAMP"),
			"peer_status_session_started_at": int64(0),
		})
	if result.Error != nil {
		return false, status.Errorf(status.Internal, "mark peer disconnected: %v", result.Error)
	}
	return result.RowsAffected > 0, nil
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

// RefreshPeerLastSeen updates only peer_status_last_seen. Every other status
// column is left untouched: peer_status_connected and
// peer_status_session_started_at belong to the sync stream that owns the
// session, and a blind write here would corrupt the fencing
// MarkPeerConnectedIfNewerSession relies on.
//
// LastSeen comes from the database clock for the same reason it does there: a
// Go-side timestamp is taken before the write and can land after a connect that
// used CURRENT_TIMESTAMP, dragging the column backwards.
//
// staleBefore carries the caller's throttle into the same statement, so
// concurrent requests for one peer collapse into a single write instead of
// each racing on its own stale read. The column is nullable — Status is an
// embedded pointer, so a peer stored without one leaves it NULL — and NULL
// loses every comparison, hence the explicit branch for a peer never seen.
func (s *SqlStore) RefreshPeerLastSeen(ctx context.Context, accountID, peerID string, staleBefore time.Time) (bool, error) {
	result := s.db.WithContext(ctx).
		Model(&nbpeer.Peer{}).
		Where(accountAndIDQueryCondition, accountID, peerID).
		Where("(peer_status_last_seen IS NULL OR peer_status_last_seen < ?)", staleBefore).
		Update("peer_status_last_seen", gorm.Expr("CURRENT_TIMESTAMP"))
	if result.Error != nil {
		return false, status.Errorf(status.Internal, "refresh peer last seen: %v", result.Error)
	}

	return result.RowsAffected > 0, nil
}

func (s *SqlStore) getPeers(ctx context.Context, accountID string) ([]nbpeer.Peer, error) {
	const query = `SELECT id, account_id, key, ip, name, dns_label, user_id, ssh_key, ssh_enabled, login_expiration_enabled,
	inactivity_expiration_enabled, last_login, created_at, ephemeral, extra_dns_labels, allow_extra_dns_labels, meta_hostname,
	meta_go_os, meta_kernel, meta_core, meta_platform, meta_os, meta_os_version, meta_wt_version, meta_ui_version,
	meta_kernel_version, meta_network_addresses, meta_system_serial_number, meta_system_product_name, meta_system_manufacturer,
	meta_environment, meta_flags, meta_files, meta_capabilities, peer_status_last_seen, peer_status_session_started_at,
	peer_status_connected, peer_status_login_expired, peer_status_requires_approval, location_connection_ip,
	location_country_code, location_city_name, location_geo_name_id, proxy_meta_embedded, proxy_meta_cluster, ipv6, meta_sync_message_version
	FROM peers WHERE account_id = $1`
	rows, err := s.pool.Query(ctx, query, accountID)
	if err != nil {
		return nil, err
	}

	peers, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (nbpeer.Peer, error) {
		var p nbpeer.Peer
		p.Status = &nbpeer.PeerStatus{}
		var (
			lastLogin, createdAt                                                                            sql.NullTime
			sshEnabled, loginExpirationEnabled, inactivityExpirationEnabled, ephemeral, allowExtraDNSLabels sql.NullBool
			peerStatusLastSeen                                                                              sql.NullTime
			peerStatusSessionStartedAt                                                                      sql.NullInt64
			peerStatusConnected, peerStatusLoginExpired, peerStatusRequiresApproval, proxyEmbedded          sql.NullBool
			ip, extraDNS, netAddr, env, flags, files, capabilities, connIP, ipv6                            []byte
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
			&metaSystemSerialNumber, &metaSystemProductName, &metaSystemManufacturer, &env, &flags, &files, &capabilities,
			&peerStatusLastSeen, &peerStatusSessionStartedAt, &peerStatusConnected, &peerStatusLoginExpired,
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
			if peerStatusLastSeen.Valid {
				p.Status.LastSeen = peerStatusLastSeen.Time
			}
			if peerStatusSessionStartedAt.Valid {
				p.Status.SessionStartedAt = peerStatusSessionStartedAt.Int64
			}
			if peerStatusConnected.Valid {
				p.Status.Connected = peerStatusConnected.Bool
			}
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
	result := s.db.Select("account_id").Take(&peer, GetKeyQueryCondition(s), peerKey)

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
	result := s.db.Model(&peer).Select("account_id").Where(GetKeyQueryCondition(s), peerKey).Take(&accountID)
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
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var peer nbpeer.Peer
	result := tx.Take(&peer, GetKeyQueryCondition(s), peerKey)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.NewPeerNotFoundError(peerKey)
		}
		return nil, status.Errorf(status.Internal, "issue getting peer from store: %s", result.Error)
	}

	return &peer, nil
}

// GetAccountPeers retrieves peers for an account.
func (s *SqlStore) GetAccountPeers(ctx context.Context, lockStrength LockingStrength, accountID, nameFilter, ipFilter string) ([]*nbpeer.Peer, error) {
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

	if err := query.Find(&peers).Error; err != nil {
		log.WithContext(ctx).Errorf("failed to get peers from the store: %s", err)
		return nil, status.Errorf(status.Internal, "failed to get peers from store")
	}

	return peers, nil
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

	return peers, nil
}

func (s *SqlStore) AddPeerToAccount(ctx context.Context, peer *nbpeer.Peer) error {
	if err := s.db.Create(peer).Error; err != nil {
		return status.Errorf(status.Internal, "issue adding peer to account: %s", err)
	}

	return nil
}

// GetPeerByID retrieves a peer by its ID and account ID.
func (s *SqlStore) GetPeerByID(ctx context.Context, lockStrength LockingStrength, accountID, peerID string) (*nbpeer.Peer, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var peer *nbpeer.Peer
	result := tx.
		Take(&peer, accountAndIDQueryCondition, accountID, peerID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.NewPeerNotFoundError(peerID)
		}
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

	return allEphemeralPeers, nil
}

// DeletePeer removes a peer from the store.
func (s *SqlStore) DeletePeer(ctx context.Context, accountID string, peerID string) error {
	result := s.db.Delete(&nbpeer.Peer{}, accountAndIDQueryCondition, accountID, peerID)
	if err := result.Error; err != nil {
		log.WithContext(ctx).Errorf("failed to delete peer from the store: %s", err)
		return status.Errorf(status.Internal, "failed to delete peer from store")
	}

	if result.RowsAffected == 0 {
		return status.NewPeerNotFoundError(peerID)
	}

	return nil
}

func (s *SqlStore) GetPeerByIP(ctx context.Context, lockStrength LockingStrength, accountID string, ip net.IP) (*nbpeer.Peer, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	column := "ip"
	if ip.To4() == nil {
		column = "ipv6"
	}
	jsonValue := fmt.Sprintf(`"%s"`, ip.String())

	var peer nbpeer.Peer
	result := tx.
		Take(&peer, fmt.Sprintf("account_id = ? AND %s = ?", column), accountID, jsonValue)
	if result.Error != nil {
		// A tunnel-IP miss is an expected outcome (e.g. the proxy's
		// ValidateTunnelPeer probing an address that isn't in the
		// account roster); surface it as NotFound so callers can tell
		// it apart from a real store failure.
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(status.NotFound, "peer with ip %s not found", ip.String())
		}
		return nil, status.Errorf(status.Internal, "failed to get peer from store")
	}

	return &peer, nil
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

	if peerID == "" {
		return "", gorm.ErrRecordNotFound
	}

	return peerID, result.Error
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
		Take(&userID, GetKeyQueryCondition(s), peerKey)

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
		Where(GetKeyQueryCondition(s), key).
		Limit(1).
		Scan(&peerID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get peer ID by key: %s", result.Error)
		return "", status.Errorf(status.Internal, "failed to get peer ID by key")
	}

	return peerID, nil
}
