package manager

import (
	"context"
	"errors"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/netbirdio/netbird/management/internals/modules/exitnodes"
	"github.com/netbirdio/netbird/management/internals/shared/db"
	"github.com/netbirdio/netbird/shared/management/status"
)

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

func (r *sqlRepository) LockAccount(ctx context.Context, accountID string) error {
	var ids []string
	err := withLock(r.db, db.LockingStrengthUpdate).Table("accounts").Where("id = ?", accountID).Pluck("id", &ids).Error
	if err != nil {
		log.WithContext(ctx).WithField("account_id", accountID).Errorf("failed to lock account: %v", err)
		return status.Errorf(status.Internal, "failed to lock account")
	}
	if len(ids) == 0 {
		return status.NewAccountNotFoundError(accountID)
	}
	return nil
}

func (r *sqlRepository) IncrementNetworkSerial(ctx context.Context, accountID string) error {
	result := r.db.Table("accounts").Where("id = ?", accountID).Update("network_serial", gorm.Expr("network_serial + 1"))
	if result.Error != nil {
		log.WithContext(ctx).WithField("account_id", accountID).Errorf("failed to increment network serial: %v", result.Error)
		return status.Errorf(status.Internal, "failed to increment network serial")
	}
	if result.RowsAffected == 0 {
		return status.NewAccountNotFoundError(accountID)
	}
	return nil
}

func (r *sqlRepository) ListByAccount(ctx context.Context, lockStrength db.LockingStrength, accountID string) ([]*exitnodes.ExitNode, error) {
	query := withLock(r.db, lockStrength).Preload("Peers", orderPeers)

	var nodes []*exitnodes.ExitNode
	if err := query.Where("account_id = ?", accountID).Order("name").Find(&nodes).Error; err != nil {
		log.WithContext(ctx).WithField("account_id", accountID).Errorf("failed to list exit nodes: %v", err)
		return nil, status.Errorf(status.Internal, "failed to list exit nodes")
	}
	return nodes, nil
}

func (r *sqlRepository) Get(ctx context.Context, lockStrength db.LockingStrength, accountID string, exitNodeID exitnodes.ID) (*exitnodes.ExitNode, error) {
	query := withLock(r.db, lockStrength).Preload("Peers", orderPeers)

	var node exitnodes.ExitNode
	err := query.Where("account_id = ? AND id = ?", accountID, exitNodeID).Take(&node).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, exitnodes.NewNotFoundError(exitNodeID)
	}
	if err != nil {
		log.WithContext(ctx).WithFields(log.Fields{"account_id": accountID, "exit_node_id": exitNodeID}).Errorf("failed to get exit node: %v", err)
		return nil, status.Errorf(status.Internal, "failed to get exit node")
	}
	return &node, nil
}

func (r *sqlRepository) Create(ctx context.Context, exitNode *exitnodes.ExitNode) error {
	if err := r.db.Omit("Peers").Create(exitNode).Error; err != nil {
		log.WithContext(ctx).WithFields(log.Fields{"account_id": exitNode.AccountID, "exit_node_id": exitNode.ID}).Errorf("failed to create exit node: %v", err)
		return status.Errorf(status.Internal, "failed to create exit node")
	}
	return r.createPeers(ctx, exitNode)
}

func (r *sqlRepository) Update(ctx context.Context, exitNode *exitnodes.ExitNode) error {
	fields := log.Fields{"account_id": exitNode.AccountID, "exit_node_id": exitNode.ID}

	// RowsAffected is not checked: MySQL reports 0 when no column changes.
	err := r.db.Model(&exitnodes.ExitNode{}).
		Where("account_id = ? AND id = ?", exitNode.AccountID, exitNode.ID).
		Select("name", "description", "enabled", "auto_apply").
		Updates(exitNode).Error
	if err != nil {
		log.WithContext(ctx).WithFields(fields).Errorf("failed to update exit node: %v", err)
		return status.Errorf(status.Internal, "failed to update exit node")
	}

	if err := r.db.Where("exit_node_id = ?", exitNode.ID).Delete(&exitnodes.Peer{}).Error; err != nil {
		log.WithContext(ctx).WithFields(fields).Errorf("failed to delete exit node peers: %v", err)
		return status.Errorf(status.Internal, "failed to update exit node")
	}
	return r.createPeers(ctx, exitNode)
}

func (r *sqlRepository) Delete(ctx context.Context, accountID string, exitNodeID exitnodes.ID) error {
	fields := log.Fields{"account_id": accountID, "exit_node_id": exitNodeID}

	if err := r.db.Where("account_id = ? AND exit_node_id = ?", accountID, exitNodeID).Delete(&exitnodes.Peer{}).Error; err != nil {
		log.WithContext(ctx).WithFields(fields).Errorf("failed to delete exit node peers: %v", err)
		return status.Errorf(status.Internal, "failed to delete exit node")
	}

	result := r.db.Where("account_id = ? AND id = ?", accountID, exitNodeID).Delete(&exitnodes.ExitNode{})
	if result.Error != nil {
		log.WithContext(ctx).WithFields(fields).Errorf("failed to delete exit node: %v", result.Error)
		return status.Errorf(status.Internal, "failed to delete exit node")
	}
	if result.RowsAffected == 0 {
		return exitnodes.NewNotFoundError(exitNodeID)
	}
	return nil
}

func (r *sqlRepository) createPeers(ctx context.Context, exitNode *exitnodes.ExitNode) error {
	if len(exitNode.Peers) == 0 {
		return nil
	}

	exitNode.BindPeers()
	if err := r.db.Create(&exitNode.Peers).Error; err != nil {
		log.WithContext(ctx).WithFields(log.Fields{"account_id": exitNode.AccountID, "exit_node_id": exitNode.ID}).Errorf("failed to create exit node peers: %v", err)
		return status.Errorf(status.Internal, "failed to save exit node peers")
	}
	return nil
}

func withLock(query *gorm.DB, lockStrength db.LockingStrength) *gorm.DB {
	if lockStrength != db.LockingStrengthNone {
		return query.Clauses(clause.Locking{Strength: string(lockStrength)})
	}
	return query
}

func orderPeers(query *gorm.DB) *gorm.DB {
	return query.Order("metric, peer_id")
}
