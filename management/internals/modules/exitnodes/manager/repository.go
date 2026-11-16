package manager

import (
	"context"
	"errors"
	"hash/fnv"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/netbirdio/netbird/management/internals/modules/exitnodes"
	"github.com/netbirdio/netbird/management/internals/shared/db"
	"github.com/netbirdio/netbird/shared/management/status"
)

const accountLockNamespace = "exit_nodes:"

type sqlRepository struct {
	conn *db.Conn
	db   *gorm.DB
}

// NewRepository returns the exit node repository backed by conn.
func NewRepository(conn *db.Conn) exitnodes.Repository {
	return &sqlRepository{conn: conn, db: conn.DB(nil)}
}

func (r *sqlRepository) WithTx(tx *db.Tx) exitnodes.Repository {
	return &sqlRepository{conn: r.conn, db: r.conn.DB(tx)}
}

// LockAccount takes a transaction-scoped advisory lock on Postgres. Row locks
// cannot stop two transactions from inserting rows the other cannot see yet.
// SQLite runs on a single connection, so its transactions are already serial.
func (r *sqlRepository) LockAccount(ctx context.Context, accountID string) error {
	if r.conn.Engine() != db.PostgresStoreEngine {
		return nil
	}

	if err := r.db.Exec("SELECT pg_advisory_xact_lock(?)", accountLockKey(accountID)).Error; err != nil {
		log.WithContext(ctx).WithField("account_id", accountID).Errorf("failed to lock exit nodes: %v", err)
		return status.Errorf(status.Internal, "failed to lock exit nodes")
	}
	return nil
}

func accountLockKey(accountID string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(accountLockNamespace + accountID))
	return int64(h.Sum64())
}

func (r *sqlRepository) ListByAccount(ctx context.Context, lockStrength db.LockingStrength, accountID string) ([]*exitnodes.ExitNode, error) {
	query := r.db.Where("account_id = ?", accountID).Order("created_at, id")
	if lockStrength != db.LockingStrengthNone {
		query = query.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var nodes []*exitnodes.ExitNode
	if err := query.Find(&nodes).Error; err != nil {
		log.WithContext(ctx).WithField("account_id", accountID).Errorf("failed to list exit nodes: %v", err)
		return nil, status.Errorf(status.Internal, "failed to get exit nodes from store")
	}
	return nodes, nil
}

func (r *sqlRepository) GetByID(ctx context.Context, lockStrength db.LockingStrength, accountID, exitNodeID string) (*exitnodes.ExitNode, error) {
	query := r.db.Where("account_id = ? AND id = ?", accountID, exitNodeID)
	if lockStrength != db.LockingStrengthNone {
		query = query.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var node exitnodes.ExitNode
	if err := query.Take(&node).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, newNotFoundError(exitNodeID)
		}
		log.WithContext(ctx).WithFields(log.Fields{
			"account_id":   accountID,
			"exit_node_id": exitNodeID,
		}).Errorf("failed to get exit node: %v", err)
		return nil, status.Errorf(status.Internal, "failed to get exit node from store")
	}
	return &node, nil
}

func (r *sqlRepository) Create(ctx context.Context, exitNode *exitnodes.ExitNode) error {
	if err := r.db.Create(exitNode).Error; err != nil {
		log.WithContext(ctx).WithFields(log.Fields{
			"account_id":   exitNode.AccountID,
			"exit_node_id": exitNode.ID,
		}).Errorf("failed to create exit node: %v", err)
		return status.Errorf(status.Internal, "failed to save exit node to store")
	}
	return nil
}

// Update replaces every column of the stored exit node with the given one.
func (r *sqlRepository) Update(ctx context.Context, exitNode *exitnodes.ExitNode) error {
	result := r.db.Model(exitNode).Where("account_id = ?", exitNode.AccountID).Select("*").Updates(exitNode)
	if result.Error != nil {
		log.WithContext(ctx).WithFields(log.Fields{
			"account_id":   exitNode.AccountID,
			"exit_node_id": exitNode.ID,
		}).Errorf("failed to update exit node: %v", result.Error)
		return status.Errorf(status.Internal, "failed to save exit node to store")
	}
	if result.RowsAffected == 0 {
		return newNotFoundError(exitNode.ID)
	}
	return nil
}

func (r *sqlRepository) Delete(ctx context.Context, accountID, exitNodeID string) error {
	result := r.db.Where("account_id = ? AND id = ?", accountID, exitNodeID).Delete(&exitnodes.ExitNode{})
	if result.Error != nil {
		log.WithContext(ctx).WithFields(log.Fields{
			"account_id":   accountID,
			"exit_node_id": exitNodeID,
		}).Errorf("failed to delete exit node: %v", result.Error)
		return status.Errorf(status.Internal, "failed to delete exit node from store")
	}
	if result.RowsAffected == 0 {
		return newNotFoundError(exitNodeID)
	}
	return nil
}

func newNotFoundError(exitNodeID string) error {
	return status.Errorf(status.NotFound, "exit node %s not found", exitNodeID)
}
