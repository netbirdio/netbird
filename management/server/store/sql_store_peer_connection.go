package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

const (
	// peerConnectionChunkSize bounds the rows per statement so the bound parameter
	// count stays below the database limits.
	peerConnectionChunkSize = 1000

	fenceNewer       = "<"
	fenceNewerOrSame = "<="
)

// staleThreshold returns an SQL expression for the database's current time minus
// nbpeer.StaleAfter, with its bound argument.
func (s *SqlStore) staleThreshold() (string, any) {
	return staleThresholdFor(s.conn.Engine())
}

// staleThresholdFor is staleThreshold for the given engine.
func staleThresholdFor(engine types.Engine) (string, any) {
	if engine == types.SqliteStoreEngine {
		return "datetime('now', ?)", fmt.Sprintf("-%d seconds", int(nbpeer.StaleAfter.Seconds()))
	}
	return "(now() - make_interval(secs => ?))", nbpeer.StaleAfter.Seconds()
}

// RegisterInstance records a management instance as alive, stamping StartedAt and
// LastSeen with the database clock.
func (s *SqlStore) RegisterInstance(ctx context.Context, id, hostname string) error {
	err := s.db.WithContext(ctx).Exec(
		`INSERT INTO management_instances (id, hostname, started_at, last_seen)
		VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT (id) DO UPDATE SET hostname = excluded.hostname,
		started_at = CURRENT_TIMESTAMP, last_seen = CURRENT_TIMESTAMP`,
		id, hostname,
	).Error
	if err != nil {
		return status.Errorf(status.Internal, "register instance: %v", err)
	}
	return nil
}

// HeartbeatInstance stamps the instance's LastSeen with the database clock. It returns
// false when the row is missing or already stale, in which case the instance may have
// been swept and must register under a new ID.
func (s *SqlStore) HeartbeatInstance(ctx context.Context, id string) (bool, error) {
	threshold, arg := s.staleThreshold()
	result := s.db.WithContext(ctx).Exec(
		"UPDATE management_instances SET last_seen = CURRENT_TIMESTAMP WHERE id = ? AND last_seen > "+threshold,
		id, arg,
	)
	if result.Error != nil {
		return false, status.Errorf(status.Internal, "heartbeat instance: %v", result.Error)
	}
	return result.RowsAffected > 0, nil
}

// raiseLastSeenTo returns the SQL expression that sets last_seen to the stamp expression
// unless it is already later.
func raiseLastSeenTo(stamp string) string {
	return "CASE WHEN last_seen IS NULL OR last_seen < " + stamp + " THEN " + stamp + " ELSE last_seen END"
}

// orphanedInstanceIDsQuery walks the distinct non-NULL instance_id values of
// peer_connections through the instance_id index, one probe per distinct value, and keeps
// those without an instance row.
const orphanedInstanceIDsQuery = `WITH RECURSIVE ids(id) AS (
	SELECT MIN(instance_id) FROM peer_connections
	UNION ALL
	SELECT (SELECT MIN(instance_id) FROM peer_connections WHERE instance_id > ids.id) FROM ids WHERE ids.id IS NOT NULL
)
SELECT id FROM ids WHERE id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM management_instances mi WHERE mi.id = ids.id)`

// ListStaleInstances returns the instances whose LastSeen is older than nbpeer.StaleAfter
// by the database clock, followed by the instance IDs that hold connections but have no
// instance row. The latter carry a zero LastSeen.
func (s *SqlStore) ListStaleInstances(ctx context.Context) ([]nbpeer.ManagementInstance, error) {
	threshold, arg := s.staleThreshold()
	var instances []nbpeer.ManagementInstance
	err := s.db.WithContext(ctx).
		Where("last_seen < "+threshold, arg).
		Find(&instances).Error
	if err != nil {
		return nil, status.Errorf(status.Internal, "list stale instances: %v", err)
	}

	var orphanIDs []string
	if err := s.db.WithContext(ctx).Raw(orphanedInstanceIDsQuery).Scan(&orphanIDs).Error; err != nil {
		return nil, status.Errorf(status.Internal, "list orphaned instances: %v", err)
	}
	for _, id := range orphanIDs {
		instances = append(instances, nbpeer.ManagementInstance{ID: id})
	}
	return instances, nil
}

// SweepInstanceChunk releases up to limit connections of a stale instance and raises the
// affected peers' LastSeen to lastSeen, the instance's own last heartbeat. A zero lastSeen,
// as of an instance without a row, raises it to the database clock instead. A peer's
// LastSeen never moves backwards. Connections that moved to another instance since the
// chunk was selected, and instances that are not stale, are left alone. It returns the
// number of connections released; zero means the instance is drained.
func (s *SqlStore) SweepInstanceChunk(ctx context.Context, instanceID string, lastSeen time.Time, limit int) (int, error) {
	threshold, arg := s.staleThreshold()

	stamp := "CURRENT_TIMESTAMP"
	var args []any
	if !lastSeen.IsZero() {
		stamp = "?"
		args = append(args, lastSeen.UTC(), lastSeen.UTC())
	}
	args = append(args, instanceID, instanceID, limit, instanceID, arg)

	result := s.db.WithContext(ctx).Exec(
		`UPDATE peer_connections SET last_seen = `+raiseLastSeenTo(stamp)+`, instance_id = NULL
		WHERE instance_id = ?
		AND peer_id IN (SELECT peer_id FROM peer_connections WHERE instance_id = ? LIMIT ?)
		AND NOT EXISTS (SELECT 1 FROM management_instances WHERE id = ? AND last_seen >= `+threshold+`)`,
		args...,
	)
	if result.Error != nil {
		return 0, status.Errorf(status.Internal, "sweep instance %s: %v", instanceID, result.Error)
	}
	return int(result.RowsAffected), nil
}

// DeleteInstanceIfStale removes the instance row when its LastSeen is still older than
// nbpeer.StaleAfter. It returns true when the row was deleted.
func (s *SqlStore) DeleteInstanceIfStale(ctx context.Context, id string) (bool, error) {
	threshold, arg := s.staleThreshold()
	result := s.db.WithContext(ctx).Exec(
		"DELETE FROM management_instances WHERE id = ? AND last_seen < "+threshold,
		id, arg,
	)
	if result.Error != nil {
		return false, status.Errorf(status.Internal, "delete stale instance: %v", result.Error)
	}
	return result.RowsAffected > 0, nil
}

// ReleaseInstance retires an instance on clean shutdown: the connections it holds are
// released with their LastSeen stamped with the database clock, then its instance row is
// deleted.
func (s *SqlStore) ReleaseInstance(ctx context.Context, id string) error {
	err := s.transaction(ctx, func(tx *gorm.DB) error {
		err := tx.Exec(
			"UPDATE peer_connections SET last_seen = "+raiseLastSeenTo("CURRENT_TIMESTAMP")+", instance_id = NULL WHERE instance_id = ?", id,
		).Error
		if err != nil {
			return fmt.Errorf("release connections: %w", err)
		}
		if err := tx.Delete(&nbpeer.ManagementInstance{}, "id = ?", id).Error; err != nil {
			return fmt.Errorf("delete instance: %w", err)
		}
		return nil
	})
	if err != nil {
		return status.Errorf(status.Internal, "release instance %s: %v", id, err)
	}
	return nil
}

// ConnectPeer makes the instance the holder of the peer's connection, but only when
// session is strictly newer than the stored one, and stamps LastSeen with the database
// clock. It returns false when a newer session already holds the peer.
func (s *SqlStore) ConnectPeer(ctx context.Context, accountID, peerID, instanceID string, session int64) (bool, error) {
	rows, err := upsertPeerConnections(s.db.WithContext(ctx), instanceID, []types.PeerSession{{
		AccountID: accountID, PeerID: peerID, SessionStartedAt: session,
	}}, fenceNewer)
	if err != nil {
		return false, status.Errorf(status.Internal, "connect peer: %v", err)
	}
	return rows > 0, nil
}

// DisconnectPeer ends the account's peer connection of session, whether an instance still
// holds it or a sweep already released it. LastSeen is raised to the database clock and
// the stored session advances by one so that a re-registration of the ended session no
// longer matches. It returns false when a newer session has replaced it or the peer does
// not exist.
func (s *SqlStore) DisconnectPeer(ctx context.Context, accountID, peerID string, session int64) (bool, error) {
	result := s.db.WithContext(ctx).Exec(
		`UPDATE peer_connections
		SET last_seen = `+raiseLastSeenTo("CURRENT_TIMESTAMP")+`, instance_id = NULL, session_started_at = session_started_at + 1
		WHERE account_id = ? AND peer_id = ? AND session_started_at = ?`,
		accountID, peerID, session,
	)
	if result.Error != nil {
		return false, status.Errorf(status.Internal, "disconnect peer: %v", result.Error)
	}
	return result.RowsAffected > 0, nil
}

// ReleasePeerConnection releases the peer's connection whatever its session. LastSeen is
// stamped with the database clock only when an instance held the connection. The stored
// session advances by one so that a re-registration of the released session no longer
// matches, while any later session still claims the peer.
func (s *SqlStore) ReleasePeerConnection(ctx context.Context, peerID string) error {
	err := s.db.WithContext(ctx).Exec(
		`UPDATE peer_connections
		SET last_seen = CASE WHEN instance_id IS NOT NULL THEN CURRENT_TIMESTAMP ELSE last_seen END,
		instance_id = NULL, session_started_at = session_started_at + 1
		WHERE peer_id = ?`,
		peerID,
	).Error
	if err != nil {
		return status.Errorf(status.Internal, "release peer connection: %v", err)
	}
	return nil
}

// ReRegisterPeers re-points the connections of sessions at the instance, in chunks. A
// connection is only overwritten by a session that is the same or newer. A failed chunk
// does not stop the others, only a done ctx does; the error joins the failures.
func (s *SqlStore) ReRegisterPeers(ctx context.Context, instanceID string, sessions []types.PeerSession) error {
	var errs []error
	for start := 0; start < len(sessions); start += peerConnectionChunkSize {
		if err := ctx.Err(); err != nil {
			errs = append(errs, status.Errorf(status.Internal, "re-register peers: %v", err))
			break
		}
		end := min(start+peerConnectionChunkSize, len(sessions))
		if _, err := upsertPeerConnections(s.db.WithContext(ctx), instanceID, sessions[start:end], fenceNewerOrSame); err != nil {
			errs = append(errs, status.Errorf(status.Internal, "re-register peers: %v", err))
		}
	}
	return errors.Join(errs...)
}

// upsertPeerConnections makes the instance hold the connections of sessions, stamping
// LastSeen with the database clock. Sessions of peers that no longer exist, or that belong
// to another account than the session names, are skipped. An
// existing connection of the same peer is only overwritten when its stored session
// compares to the incoming one by fence. It returns the number of connections inserted or
// overwritten.
func upsertPeerConnections(tx *gorm.DB, instanceID string, sessions []types.PeerSession, fence string) (int64, error) {
	placeholders := strings.TrimSuffix(strings.Repeat("(CAST(? AS TEXT), CAST(? AS TEXT), CAST(? AS TEXT), CAST(? AS BIGINT)), ", len(sessions)), ", ")
	args := make([]any, 0, len(sessions)*4)
	for _, session := range sessions {
		args = append(args, session.PeerID, session.AccountID, instanceID, session.SessionStartedAt)
	}

	result := tx.Exec(
		`WITH incoming (peer_id, account_id, instance_id, session_started_at) AS (VALUES `+placeholders+`)
		INSERT INTO peer_connections (peer_id, account_id, instance_id, session_started_at, last_seen)
		SELECT incoming.peer_id, incoming.account_id, incoming.instance_id, incoming.session_started_at, CURRENT_TIMESTAMP
		FROM incoming JOIN peers ON peers.id = incoming.peer_id AND peers.account_id = incoming.account_id WHERE true
		ON CONFLICT (peer_id) DO UPDATE SET account_id = excluded.account_id,
		instance_id = excluded.instance_id, session_started_at = excluded.session_started_at,
		last_seen = CURRENT_TIMESTAMP
		WHERE peer_connections.session_started_at `+fence+` excluded.session_started_at`,
		args...,
	)
	if result.Error != nil {
		return 0, fmt.Errorf("upsert connections: %w", result.Error)
	}
	return result.RowsAffected, nil
}

// createPeerConnections records the liveness of newly created peers: no instance holds
// them and they were last seen as their status says. Peers that already have a record
// keep it.
func createPeerConnections(tx *gorm.DB, peers ...*nbpeer.Peer) error {
	conns := make([]nbpeer.Connection, 0, len(peers))
	for _, peer := range peers {
		conn := nbpeer.Connection{PeerID: peer.ID, AccountID: peer.AccountID}
		if peer.Status != nil && !peer.Status.LastSeen.IsZero() {
			lastSeen := peer.Status.LastSeen.UTC()
			conn.LastSeen = &lastSeen
		}
		conns = append(conns, conn)
	}
	if len(conns) == 0 {
		return nil
	}

	err := tx.Clauses(clause.OnConflict{DoNothing: true}).CreateInBatches(conns, peerConnectionChunkSize).Error
	if err != nil {
		return fmt.Errorf("create peer connections: %w", err)
	}
	return nil
}

// peerConnectionRow is a peer's connection row joined with the LastSeen of the instance
// holding it.
type peerConnectionRow struct {
	PeerID           string
	SessionStartedAt int64
	LastSeen         sql.NullTime
	InstanceLastSeen sql.NullTime
}

func (s *SqlStore) peerConnectionRows() *gorm.DB {
	return s.db.Table("peer_connections AS pc").
		Select("pc.peer_id, pc.session_started_at, pc.last_seen, mi.last_seen AS instance_last_seen").
		Joins("LEFT JOIN management_instances mi ON mi.id = pc.instance_id")
}

// attachPeerConnections derives the connection status of the peers from their connection
// rows. Peers without one read as disconnected and never seen.
func (s *SqlStore) attachPeerConnections(ctx context.Context, peers ...*nbpeer.Peer) error {
	rows := make(map[string]peerConnectionRow, len(peers))
	for start := 0; start < len(peers); start += peerConnectionChunkSize {
		end := min(start+peerConnectionChunkSize, len(peers))
		ids := make([]string, 0, end-start)
		for _, peer := range peers[start:end] {
			ids = append(ids, peer.ID)
		}

		var chunk []peerConnectionRow
		if err := s.peerConnectionRows().WithContext(ctx).Where("pc.peer_id IN ?", ids).Scan(&chunk).Error; err != nil {
			return fmt.Errorf("load peer connections: %w", err)
		}
		for _, row := range chunk {
			rows[row.PeerID] = row
		}
	}

	for _, peer := range peers {
		applyPeerConnection(peer, rows)
	}
	return nil
}

// attachAccountPeerConnections is attachPeerConnections for all peers of an account
// loaded in one go, using a single account-scoped query.
func (s *SqlStore) attachAccountPeerConnections(ctx context.Context, accountID string, peers []nbpeer.Peer) error {
	var list []peerConnectionRow
	if err := s.peerConnectionRows().WithContext(ctx).Where("pc.account_id = ?", accountID).Scan(&list).Error; err != nil {
		return fmt.Errorf("load account peer connections: %w", err)
	}
	rows := make(map[string]peerConnectionRow, len(list))
	for _, row := range list {
		rows[row.PeerID] = row
	}

	for i := range peers {
		applyPeerConnection(&peers[i], rows)
	}
	return nil
}

func applyPeerConnection(peer *nbpeer.Peer, rows map[string]peerConnectionRow) {
	row, ok := rows[peer.ID]
	if peer.Status == nil {
		peer.Status = &nbpeer.PeerStatus{}
	}
	peer.Status.ApplyConnection(sql.NullInt64{Int64: row.SessionStartedAt, Valid: ok}, row.LastSeen, row.InstanceLastSeen)
}

// peerWithConnection is a peer row joined with its connection row and the holding
// instance.
type peerWithConnection struct {
	nbpeer.Peer
	ConnSessionStartedAt sql.NullInt64
	ConnLastSeen         sql.NullTime
	ConnInstanceLastSeen sql.NullTime
}

// takePeerWithConnection loads the one peer matching the condition together with its
// liveness in a single query. The condition must qualify its columns with peers. A held
// lock covers only the peers row. It returns gorm.ErrRecordNotFound when no peer matches.
func (s *SqlStore) takePeerWithConnection(ctx context.Context, lockStrength LockingStrength, condition string, args ...any) (*nbpeer.Peer, error) {
	tx := s.db.WithContext(ctx)
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength), Table: clause.Table{Name: "peers"}})
	}

	var row peerWithConnection
	err := tx.Table("peers").
		Select("peers.*, pc.session_started_at AS conn_session_started_at, pc.last_seen AS conn_last_seen, mi.last_seen AS conn_instance_last_seen").
		Joins("LEFT JOIN peer_connections pc ON pc.peer_id = peers.id").
		Joins("LEFT JOIN management_instances mi ON mi.id = pc.instance_id").
		Where(condition, args...).
		Take(&row).Error
	if err != nil {
		return nil, err
	}

	peer := row.Peer
	if peer.Status == nil {
		peer.Status = &nbpeer.PeerStatus{}
	}
	peer.Status.ApplyConnection(row.ConnSessionStartedAt, row.ConnLastSeen, row.ConnInstanceLastSeen)
	return &peer, nil
}
