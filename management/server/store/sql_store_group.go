package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

// CreateGroups creates the given list of groups to the database.
// groupUpsertColumns is the explicit allowlist of columns that get updated when
// CreateGroups / UpdateGroups hit a PK conflict. public_id is intentionally
// omitted so a caller passing an entity with the zero value (e.g. an HTTP
// handler-built struct) cannot reset the persisted public_id during an upsert.
// Keep this in sync with the Group schema in management/server/types/group.go.
func groupUpsertColumns() clause.Set {
	return clause.AssignmentColumns([]string{
		"account_id",
		"name",
		"issued",
		"integration_ref_id",
		"integration_ref_integration_type",
		"resources",
	})
}

func (s *SqlStore) CreateGroups(ctx context.Context, accountID string, groups []*types.Group) error {
	if len(groups) == 0 {
		return nil
	}

	return s.db.Transaction(func(tx *gorm.DB) error {
		result := tx.
			Clauses(
				clause.OnConflict{
					Columns:   []clause.Column{{Name: "id"}},
					Where:     clause.Where{Exprs: []clause.Expression{clause.Eq{Column: "groups.account_id", Value: accountID}}},
					DoUpdates: groupUpsertColumns(),
				},
			).
			Omit(clause.Associations).
			Create(&groups)
		if result.Error != nil {
			log.WithContext(ctx).Errorf("failed to save groups to store: %v", result.Error)
			return status.Errorf(status.Internal, "failed to save groups to store")
		}

		return nil
	})
}

// UpdateGroups updates the given list of groups to the database.
func (s *SqlStore) UpdateGroups(ctx context.Context, accountID string, groups []*types.Group) error {
	if len(groups) == 0 {
		return nil
	}

	return s.db.Transaction(func(tx *gorm.DB) error {
		result := tx.
			Clauses(
				clause.OnConflict{
					Columns:   []clause.Column{{Name: "id"}},
					Where:     clause.Where{Exprs: []clause.Expression{clause.Eq{Column: "groups.account_id", Value: accountID}}},
					DoUpdates: groupUpsertColumns(),
				},
			).
			Omit(clause.Associations).
			Create(&groups)
		if result.Error != nil {
			log.WithContext(ctx).Errorf("failed to save groups to store: %v", result.Error)
			return status.Errorf(status.Internal, "failed to save groups to store")
		}

		return nil
	})
}

func (s *SqlStore) GetAccountGroups(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*types.Group, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var groups []*types.Group
	result := tx.Preload(clause.Associations).Find(&groups, accountIDCondition, accountID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(status.NotFound, "accountID not found: index lookup failed")
		}
		log.WithContext(ctx).Errorf("failed to get account groups from the store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get account groups from the store")
	}

	for _, g := range groups {
		g.LoadGroupPeers()
	}

	return groups, nil
}

func (s *SqlStore) GetResourceGroups(ctx context.Context, lockStrength LockingStrength, accountID, resourceID string) ([]*types.Group, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var groups []*types.Group

	likePattern := `%"ID":"` + resourceID + `"%`

	result := tx.
		Preload(clause.Associations).
		Where("resources LIKE ?", likePattern).
		Find(&groups)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, result.Error
	}

	for _, g := range groups {
		g.LoadGroupPeers()
	}

	return groups, nil
}

func (s *SqlStore) getGroups(ctx context.Context, accountID string) ([]*types.Group, error) {
	const query = `SELECT id, account_id, public_id, name, issued, resources, integration_ref_id, integration_ref_integration_type FROM groups WHERE account_id = $1`
	rows, err := s.pool.Query(ctx, query, accountID)
	if err != nil {
		return nil, err
	}
	groups, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (*types.Group, error) {
		var g types.Group
		var resources []byte
		var refID sql.NullInt64
		var refType sql.NullString
		err := row.Scan(&g.ID, &g.AccountID, &g.PublicID, &g.Name, &g.Issued, &resources, &refID, &refType)
		if err == nil {
			if refID.Valid {
				g.IntegrationReference.ID = int(refID.Int64)
			}
			if refType.Valid {
				g.IntegrationReference.IntegrationType = refType.String
			}
			if resources != nil {
				_ = json.Unmarshal(resources, &g.Resources)
			} else {
				g.Resources = []types.Resource{}
			}
			g.GroupPeers = []types.GroupPeer{}
			g.Peers = []string{}
		}
		return &g, err
	})
	if err != nil {
		return nil, err
	}
	return groups, nil
}

// AddResourceToGroup adds a resource to a group. Method always needs to run n a transaction
func (s *SqlStore) AddResourceToGroup(ctx context.Context, accountId string, groupID string, resource *types.Resource) error {
	var group types.Group
	result := s.db.Where(accountAndIDQueryCondition, accountId, groupID).Take(&group)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return status.NewGroupNotFoundError(groupID)
		}

		return status.Errorf(status.Internal, "issue finding group: %s", result.Error)
	}

	for _, res := range group.Resources {
		if res.ID == resource.ID {
			return nil
		}
	}

	group.Resources = append(group.Resources, *resource)

	if err := s.db.Save(&group).Error; err != nil {
		return status.Errorf(status.Internal, "issue updating group: %s", err)
	}

	return nil
}

// RemoveResourceFromGroup removes a resource from a group. Method always needs to run in a transaction
func (s *SqlStore) RemoveResourceFromGroup(ctx context.Context, accountId string, groupID string, resourceID string) error {
	var group types.Group
	result := s.db.Where(accountAndIDQueryCondition, accountId, groupID).Take(&group)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return status.NewGroupNotFoundError(groupID)
		}

		return status.Errorf(status.Internal, "issue finding group: %s", result.Error)
	}

	for i, res := range group.Resources {
		if res.ID == resourceID {
			group.Resources = append(group.Resources[:i], group.Resources[i+1:]...)
			break
		}
	}

	if err := s.db.Save(&group).Error; err != nil {
		return status.Errorf(status.Internal, "issue updating group: %s", err)
	}

	return nil
}

// GetGroupByID retrieves a group by ID and account ID.
func (s *SqlStore) GetGroupByID(ctx context.Context, lockStrength LockingStrength, accountID, groupID string) (*types.Group, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var group *types.Group
	result := tx.Preload(clause.Associations).Take(&group, accountAndIDQueryCondition, accountID, groupID)
	if err := result.Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.NewGroupNotFoundError(groupID)
		}
		log.WithContext(ctx).Errorf("failed to get group from store: %s", err)
		return nil, status.Errorf(status.Internal, "failed to get group from store")
	}

	group.LoadGroupPeers()

	return group, nil
}

// GetGroupByName retrieves a group by name and account ID.
func (s *SqlStore) GetGroupByName(ctx context.Context, lockStrength LockingStrength, accountID, groupName string) (*types.Group, error) {
	tx := s.db

	var group types.Group

	// TODO: This fix is accepted for now, but if we need to handle this more frequently
	// we may need to reconsider changing the types.
	query := tx.Preload(clause.Associations)

	result := query.
		Model(&types.Group{}).
		Joins("LEFT JOIN group_peers ON group_peers.group_id = groups.id").
		Where("groups.account_id = ? AND groups.name = ?", accountID, groupName).
		Group("groups.id").
		Order("COUNT(group_peers.peer_id) DESC").
		Limit(1).
		First(&group)
	if err := result.Error; err != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.NewGroupNotFoundError(groupName)
		}
		log.WithContext(ctx).Errorf("failed to get group by name from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get group by name from store")
	}

	group.LoadGroupPeers()

	return &group, nil
}

// GetGroupsByIDs retrieves groups by their IDs and account ID.
func (s *SqlStore) GetGroupsByIDs(ctx context.Context, lockStrength LockingStrength, accountID string, groupIDs []string) (map[string]*types.Group, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var groups []*types.Group
	result := tx.Preload(clause.Associations).Find(&groups, accountAndIDsQueryCondition, accountID, groupIDs)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get groups by ID's from store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get groups by ID's from store")
	}

	groupsMap := make(map[string]*types.Group)
	for _, group := range groups {
		group.LoadGroupPeers()
		groupsMap[group.ID] = group
	}

	return groupsMap, nil
}

// CreateGroup creates a group in the store.
func (s *SqlStore) CreateGroup(ctx context.Context, group *types.Group) error {
	if group == nil {
		return status.Errorf(status.InvalidArgument, "group is nil")
	}

	if err := s.db.Omit(clause.Associations).Create(group).Error; err != nil {
		log.WithContext(ctx).Errorf("failed to save group to store: %v", err)
		return status.Errorf(status.Internal, "failed to save group to store")
	}

	return nil
}

// UpdateGroup updates a group in the store.
func (s *SqlStore) UpdateGroup(ctx context.Context, group *types.Group) error {
	if group == nil {
		return status.Errorf(status.InvalidArgument, "group is nil")
	}

	if err := s.db.Omit(clause.Associations, "public_id").Save(group).Error; err != nil {
		log.WithContext(ctx).Errorf("failed to save group to store: %v", err)
		return status.Errorf(status.Internal, "failed to save group to store")
	}

	return nil
}

// DeleteGroup deletes a group from the database.
func (s *SqlStore) DeleteGroup(ctx context.Context, accountID, groupID string) error {
	result := s.db.Select(clause.Associations).
		Delete(&types.Group{}, accountAndIDQueryCondition, accountID, groupID)
	if err := result.Error; err != nil {
		log.WithContext(ctx).Errorf("failed to delete group from store: %s", result.Error)
		return status.Errorf(status.Internal, "failed to delete group from store")
	}

	if result.RowsAffected == 0 {
		return status.NewGroupNotFoundError(groupID)
	}

	return nil
}

// DeleteGroups deletes groups from the database.
func (s *SqlStore) DeleteGroups(ctx context.Context, accountID string, groupIDs []string) error {
	result := s.db.Select(clause.Associations).
		Delete(&types.Group{}, accountAndIDsQueryCondition, accountID, groupIDs)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to delete groups from store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to delete groups from store")
	}

	return nil
}
