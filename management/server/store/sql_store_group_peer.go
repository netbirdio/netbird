package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

func (s *SqlStore) getGroupPeers(ctx context.Context, groupIDs []string) ([]types.GroupPeer, error) {
	if len(groupIDs) == 0 {
		return nil, nil
	}
	const query = `SELECT account_id, group_id, peer_id FROM group_peers WHERE group_id = ANY($1)`
	rows, err := s.pool.Query(ctx, query, groupIDs)
	if err != nil {
		return nil, err
	}
	groupPeers, err := pgx.CollectRows(rows, pgx.RowToStructByName[types.GroupPeer])
	if err != nil {
		return nil, err
	}
	return groupPeers, nil
}

// AddPeerToAllGroup adds a peer to the 'All' group. Method always needs to run in a transaction
func (s *SqlStore) AddPeerToAllGroup(ctx context.Context, accountID string, peerID string) error {
	var groupID string
	_ = s.db.Model(types.Group{}).
		Select("id").
		Where("account_id = ? AND name = ?", accountID, "All").
		Limit(1).
		Scan(&groupID)

	if groupID == "" {
		return status.Errorf(status.NotFound, "group 'All' not found for account %s", accountID)
	}

	err := s.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "group_id"}, {Name: "peer_id"}},
		DoNothing: true,
	}).Create(&types.GroupPeer{
		AccountID: accountID,
		GroupID:   groupID,
		PeerID:    peerID,
	}).Error
	if err != nil {
		return status.Errorf(status.Internal, "error adding peer to group 'All': %v", err)
	}

	return nil
}

// AddPeerToGroup adds a peer to a group
func (s *SqlStore) AddPeerToGroup(ctx context.Context, accountID, peerID, groupID string) error {
	peer := &types.GroupPeer{
		AccountID: accountID,
		GroupID:   groupID,
		PeerID:    peerID,
	}

	err := s.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "group_id"}, {Name: "peer_id"}},
		DoNothing: true,
	}).Create(peer).Error
	if err != nil {
		log.WithContext(ctx).Errorf("failed to add peer %s to group %s for account %s: %v", peerID, groupID, accountID, err)
		return status.Errorf(status.Internal, "failed to add peer to group")
	}

	return nil
}

// RemovePeerFromGroup removes a peer from a group
func (s *SqlStore) RemovePeerFromGroup(ctx context.Context, peerID string, groupID string) error {
	err := s.db.
		Delete(&types.GroupPeer{}, "group_id = ? AND peer_id = ?", groupID, peerID).Error
	if err != nil {
		log.WithContext(ctx).Errorf("failed to remove peer %s from group %s: %v", peerID, groupID, err)
		return status.Errorf(status.Internal, "failed to remove peer from group")
	}

	return nil
}

// RemovePeerFromAllGroups removes a peer from all groups
func (s *SqlStore) RemovePeerFromAllGroups(ctx context.Context, peerID string) error {
	err := s.db.
		Delete(&types.GroupPeer{}, "peer_id = ?", peerID).Error
	if err != nil {
		log.WithContext(ctx).Errorf("failed to remove peer %s from all groups: %v", peerID, err)
		return status.Errorf(status.Internal, "failed to remove peer from all groups")
	}

	return nil
}

// GetPeerGroups retrieves all groups assigned to a specific peer in a given account.
func (s *SqlStore) GetPeerGroups(ctx context.Context, lockStrength LockingStrength, accountId string, peerId string) ([]*types.Group, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var groups []*types.Group
	query := tx.
		Joins("JOIN group_peers ON group_peers.group_id = groups.id").
		Where("groups.account_id = ? AND group_peers.peer_id = ?", accountId, peerId).
		Preload(clause.Associations).
		Find(&groups)

	if query.Error != nil {
		return nil, query.Error
	}

	for _, group := range groups {
		group.LoadGroupPeers()
	}

	return groups, nil
}

// GetPeerGroupIDs retrieves all group IDs assigned to a specific peer in a given account.
func (s *SqlStore) GetPeerGroupIDs(ctx context.Context, lockStrength LockingStrength, accountId string, peerId string) ([]string, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var groupIDs []string
	query := tx.
		Model(&types.GroupPeer{}).
		Where("account_id = ? AND peer_id = ?", accountId, peerId).
		Pluck("group_id", &groupIDs)

	if query.Error != nil {
		if errors.Is(query.Error, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(status.NotFound, "no groups found for peer %s in account %s", peerId, accountId)
		}
		log.WithContext(ctx).Errorf("failed to get group IDs for peer %s in account %s: %v", peerId, accountId, query.Error)
		return nil, status.Errorf(status.Internal, "failed to get group IDs for peer from store")
	}

	return groupIDs, nil
}

func (s *SqlStore) GetAccountGroupPeers(ctx context.Context, lockStrength LockingStrength, accountID string) (map[string]map[string]struct{}, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var peers []types.GroupPeer
	result := tx.Find(&peers, accountIDCondition, accountID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get account group peers from store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get account group peers from store")
	}

	groupPeers := make(map[string]map[string]struct{})
	for _, peer := range peers {
		if _, exists := groupPeers[peer.GroupID]; !exists {
			groupPeers[peer.GroupID] = make(map[string]struct{})
		}
		groupPeers[peer.GroupID][peer.PeerID] = struct{}{}
	}

	return groupPeers, nil
}

func (s *SqlStore) GetPeersByGroupIDs(ctx context.Context, accountID string, groupIDs []string) ([]*nbpeer.Peer, error) {
	if len(groupIDs) == 0 {
		return []*nbpeer.Peer{}, nil
	}

	var peers []*nbpeer.Peer
	peerIDsSubquery := s.db.Model(&types.GroupPeer{}).
		Select("DISTINCT peer_id").
		Where("account_id = ? AND group_id IN ?", accountID, groupIDs)

	result := s.db.Where("account_id = ? AND id IN (?)", accountID, peerIDsSubquery).Find(&peers)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get peers by group IDs: %s", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get peers by group IDs")
	}

	return peers, nil
}

func (s *SqlStore) GetPeerIDsByGroups(ctx context.Context, accountID string, groupIDs []string) ([]string, error) {
	if len(groupIDs) == 0 {
		return nil, nil
	}

	var peerIDs []string
	result := s.db.Model(&types.GroupPeer{}).
		Select("DISTINCT peer_id").
		Where("account_id = ? AND group_id IN ?", accountID, groupIDs).
		Pluck("peer_id", &peerIDs)
	if result.Error != nil {
		return nil, status.Errorf(status.Internal, "failed to get peer IDs by groups: %s", result.Error)
	}

	return peerIDs, nil
}

func (s *SqlStore) GetGroupIDsByPeerIDs(ctx context.Context, accountID string, peerIDs []string) ([]string, error) {
	if len(peerIDs) == 0 {
		return nil, nil
	}

	var groupIDs []string
	result := s.db.Model(&types.GroupPeer{}).
		Select("DISTINCT group_id").
		Where("account_id = ? AND peer_id IN ?", accountID, peerIDs).
		Pluck("group_id", &groupIDs)
	if result.Error != nil {
		return nil, status.Errorf(status.Internal, "failed to get group IDs by peers: %s", result.Error)
	}

	return groupIDs, nil
}
