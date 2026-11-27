package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
	"github.com/netbirdio/netbird/util/crypt"
)

// SaveUsers saves the given list of users to the database.
func (s *SqlStore) SaveUsers(ctx context.Context, users []*types.User) error {
	if len(users) == 0 {
		return nil
	}

	usersCopy := make([]*types.User, len(users))
	for i, user := range users {
		userCopy := user.Copy()
		userCopy.Email = user.Email
		userCopy.Name = user.Name
		if err := userCopy.EncryptSensitiveData(s.fieldEncrypt); err != nil {
			return fmt.Errorf("encrypt user: %w", err)
		}
		usersCopy[i] = userCopy
	}

	result := s.db.Clauses(clause.OnConflict{UpdateAll: true}).Create(&usersCopy)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to save users to store: %s", result.Error)
		return status.Errorf(status.Internal, "failed to save users to store")
	}
	return nil
}

// SaveUser saves the given user to the database.
func (s *SqlStore) SaveUser(ctx context.Context, user *types.User) error {
	userCopy := user.Copy()
	userCopy.Email = user.Email
	userCopy.Name = user.Name

	if err := userCopy.EncryptSensitiveData(s.fieldEncrypt); err != nil {
		return fmt.Errorf("encrypt user: %w", err)
	}

	result := s.db.Save(userCopy)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to save user to store: %s", result.Error)
		return status.Errorf(status.Internal, "failed to save user to store")
	}
	return nil
}

func (s *SqlStore) GetUserByPATID(ctx context.Context, lockStrength LockingStrength, patID string) (*types.User, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var user types.User
	result := tx.
		Joins("JOIN personal_access_tokens ON personal_access_tokens.user_id = users.id").
		Where("personal_access_tokens.id = ?", patID).Take(&user)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.NewPATNotFoundError(patID)
		}
		log.WithContext(ctx).Errorf("failed to get token user from the store: %s", result.Error)
		return nil, status.NewGetUserFromStoreError()
	}

	if err := user.DecryptSensitiveData(s.fieldEncrypt); err != nil {
		return nil, fmt.Errorf("decrypt user: %w", err)
	}

	return &user, nil
}

func (s *SqlStore) GetUserByUserID(ctx context.Context, lockStrength LockingStrength, userID string) (*types.User, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var user types.User
	result := tx.Take(&user, idQueryCondition, userID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.NewUserNotFoundError(userID)
		}
		return nil, status.NewGetUserFromStoreError()
	}

	if err := user.DecryptSensitiveData(s.fieldEncrypt); err != nil {
		return nil, fmt.Errorf("decrypt user: %w", err)
	}

	return &user, nil
}

func (s *SqlStore) DeleteUser(ctx context.Context, accountID, userID string) error {
	err := s.transaction(ctx, func(tx *gorm.DB) error {
		result := tx.Delete(&types.PersonalAccessToken{}, "user_id = ?", userID)
		if result.Error != nil {
			return result.Error
		}

		return tx.Delete(&types.User{}, accountAndIDQueryCondition, accountID, userID).Error
	})
	if err != nil {
		log.WithContext(ctx).Errorf("failed to delete user from the store: %s", err)
		return status.Errorf(status.Internal, "failed to delete user from store")
	}

	return nil
}

func (s *SqlStore) GetAccountUsers(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*types.User, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var users []*types.User

	result := tx.Find(&users, accountIDCondition, accountID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(status.NotFound, "accountID not found: index lookup failed")
		}
		log.WithContext(ctx).Errorf("error when getting users from the store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "issue getting users from store")
	}

	for _, user := range users {
		if err := user.DecryptSensitiveData(s.fieldEncrypt); err != nil {
			return nil, fmt.Errorf("decrypt user: %w", err)
		}
	}

	return users, nil
}

func (s *SqlStore) GetAccountUsersPaginated(ctx context.Context,
	lockStrength LockingStrength,
	accountID string,
	pagination PaginationState,
	filters UserFilters,
	sorting UserSorting,
) ([]*types.User, int, error) {
	engine := s.conn.Engine()

	// A fresh statement per query keeps the page's LIMIT/OFFSET out of the count.
	listedUsers := func() *gorm.DB {
		tx := s.db
		if lockStrength != LockingStrengthNone {
			tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
		}
		tx = whereBool(tx.Where(accountIDCondition, accountID), "users.non_deletable", false)
		return filters.AsConditions(tx, engine, s.fieldEncrypt)
	}

	var users []*types.User
	{
		query := listedUsers()
		query = pagination.AsScope(query)
		query = sorting.AsOrderBy(query)

		if err := query.Find(&users).Error; err != nil {
			log.WithContext(ctx).Errorf("failed to get users from the store: %s", err)
			return nil, 0, status.Errorf(status.Internal, "failed to get users from store")
		}
	}

	var count int64
	{
		if err := listedUsers().Table("users").Select("count(distinct(users.id))").Count(&count).Error; err != nil {
			log.WithContext(ctx).Errorf("failed to get total number of users from the store: %s", err)
			return nil, 0, status.Errorf(status.Internal, "failed to get total number of users from store")
		}
	}

	for _, user := range users {
		if err := user.DecryptSensitiveData(s.fieldEncrypt); err != nil {
			return nil, 0, fmt.Errorf("decrypt user: %w", err)
		}
	}

	if filters.Name != "" {
		// the name filter also matches some users by chance; they are still counted
		users = slices.DeleteFunc(users, func(user *types.User) bool { return !user.MatchesName(filters.Name) })
	}

	return users, int(count), nil
}

// UserFilters narrows the users GetAccountUsersPaginated lists. Empty fields don't filter.
type UserFilters struct {
	// Name matches part of the name and Email the whole email, ignoring case.
	Name            string
	Email           string
	ServiceUser     *bool
	PendingApproval *bool
	Roles           []types.UserRole
	// GroupIDs matches users with any of these groups in their auto groups.
	GroupIDs []string
	UserIDs  []string
}

// AsConditions adds the filters to a users query.
func (f *UserFilters) AsConditions(db *gorm.DB, engine types.Engine, enc *crypt.FieldEncrypt) *gorm.DB {
	if f.Name != "" {
		for i, bits := range types.NameFilter(enc, f.Name) {
			if bits != 0 {
				db = db.Where(fmt.Sprintf("(users.name_hash_%d & ?) = ?", i+1), bits, bits)
			}
		}
	}
	if f.Email != "" {
		db = db.Where("users.email_hash = ?", types.EmailSearchHash(enc, f.Email))
	}
	if f.ServiceUser != nil {
		db = whereBool(db, "users.is_service_user", *f.ServiceUser)
	}
	if f.PendingApproval != nil {
		db = whereBool(db, "users.pending_approval", *f.PendingApproval)
	}
	if len(f.Roles) > 0 {
		db = db.Where("users.role IN ?", f.Roles)
	}
	if len(f.GroupIDs) > 0 {
		db = db.Where(autoGroupsMatchAnyCondition(engine), f.GroupIDs)
	}
	if len(f.UserIDs) > 0 {
		db = db.Where("users.id IN ?", f.UserIDs)
	}
	return db
}

// whereBool matches a boolean column, counting NULL as false.
func whereBool(db *gorm.DB, column string, value bool) *gorm.DB {
	if value {
		return db.Where(column+" = ?", true)
	}
	return db.Where("("+column+" = ? OR "+column+" IS NULL)", false)
}

// autoGroupsMatchAnyCondition matches users whose auto groups contain any of the given group IDs.
// The auto groups are a JSON array in a text column; any other value counts as no groups.
func autoGroupsMatchAnyCondition(engine types.Engine) string {
	if engine == types.PostgresStoreEngine {
		return `EXISTS (SELECT 1 FROM jsonb_array_elements_text(CASE WHEN users.auto_groups LIKE '[%' THEN users.auto_groups::jsonb ELSE '[]'::jsonb END) AS auto_group(id) WHERE auto_group.id IN ?)`
	}
	return `EXISTS (SELECT 1 FROM json_each(CASE WHEN json_valid(users.auto_groups) THEN users.auto_groups ELSE '[]' END) AS auto_group WHERE auto_group.value IN ?)`
}

// UserSortByField is a field the users listing can be sorted by.
type UserSortByField int

const (
	UserSortByIsCurrent UserSortByField = iota
	UserSortByRole
	UserSortByLastLogin
)

// UserSortingKey is one sort field and its direction.
type UserSortingKey struct {
	Field UserSortByField
	Order OrderBy
}

// UserSorting orders the users GetAccountUsersPaginated lists. The id always comes last,
// so pages stay stable.
type UserSorting struct {
	// CurrentUserID is the user the is_current field refers to.
	CurrentUserID string
	Fields        []UserSortingKey
}

// AsOrderBy adds the sort fields to a users query.
func (s *UserSorting) AsOrderBy(db *gorm.DB) *gorm.DB {
	// TODO: sort by name. Names are encrypted at rest, so SQL can't order them.
	var columns []string
	var vars []any
	for _, key := range s.Fields {
		direction := " ASC"
		if key.Order == DescOrderBy {
			direction = " DESC"
		}
		switch key.Field {
		case UserSortByIsCurrent:
			columns = append(columns, "CASE WHEN users.id = ? THEN 1 ELSE 0 END"+direction)
			vars = append(vars, s.CurrentUserID)
		case UserSortByRole:
			columns = append(columns, "users.role"+direction)
		case UserSortByLastLogin:
			// users who never logged in come last in both directions, as engines order NULLs differently
			columns = append(columns, "CASE WHEN users.last_login IS NULL THEN 1 ELSE 0 END", "users.last_login"+direction)
		}
	}
	columns = append(columns, "users.id")

	return db.Order(clause.OrderBy{Expression: clause.Expr{SQL: strings.Join(columns, ", "), Vars: vars}})
}

func (s *SqlStore) GetAccountOwner(ctx context.Context, lockStrength LockingStrength, accountID string) (*types.User, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var user types.User
	result := tx.Take(&user, "account_id = ? AND role = ?", accountID, types.UserRoleOwner)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(status.NotFound, "account owner not found: index lookup failed")
		}
		return nil, status.Errorf(status.Internal, "failed to get account owner from the store")
	}

	if err := user.DecryptSensitiveData(s.fieldEncrypt); err != nil {
		return nil, fmt.Errorf("decrypt user: %w", err)
	}

	return &user, nil
}

func (s *SqlStore) getUsers(ctx context.Context, accountID string) ([]types.User, error) {
	const query = `SELECT id, account_id, role, is_service_user, non_deletable, service_user_name, auto_groups, blocked, pending_approval, last_login, created_at, issued, integration_ref_id, integration_ref_integration_type, email, name FROM users WHERE account_id = $1`
	rows, err := s.pgxPool().Query(ctx, query, accountID)
	if err != nil {
		return nil, err
	}
	users, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (types.User, error) {
		var u types.User
		var autoGroups []byte
		var lastLogin, createdAt sql.NullTime
		var isServiceUser, nonDeletable, blocked, pendingApproval sql.NullBool
		err := row.Scan(&u.Id, &u.AccountID, &u.Role, &isServiceUser, &nonDeletable, &u.ServiceUserName, &autoGroups, &blocked, &pendingApproval, &lastLogin, &createdAt, &u.Issued, &u.IntegrationReference.ID, &u.IntegrationReference.IntegrationType, &u.Email, &u.Name)
		if err == nil {
			if lastLogin.Valid {
				u.LastLogin = &lastLogin.Time
			}
			if createdAt.Valid {
				u.CreatedAt = createdAt.Time
			}
			if isServiceUser.Valid {
				u.IsServiceUser = isServiceUser.Bool
			}
			if nonDeletable.Valid {
				u.NonDeletable = nonDeletable.Bool
			}
			if blocked.Valid {
				u.Blocked = blocked.Bool
			}
			if pendingApproval.Valid {
				u.PendingApproval = pendingApproval.Bool
			}
			if autoGroups != nil {
				_ = json.Unmarshal(autoGroups, &u.AutoGroups)
			} else {
				u.AutoGroups = []string{}
			}
		}
		return u, err
	})
	if err != nil {
		return nil, err
	}
	return users, nil
}

func (s *SqlStore) GetAccountByUser(ctx context.Context, userID string) (*types.Account, error) {
	var user types.User
	result := s.db.Select("account_id").Take(&user, idQueryCondition, userID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(status.NotFound, "account not found: index lookup failed")
		}
		return nil, status.NewGetAccountFromStoreError(result.Error)
	}

	if user.AccountID == "" {
		return nil, status.Errorf(status.NotFound, "account not found: index lookup failed")
	}

	return s.GetAccount(ctx, user.AccountID)
}

func (s *SqlStore) GetAccountIDByUserID(ctx context.Context, lockStrength LockingStrength, userID string) (string, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var accountID string
	result := tx.Model(&types.User{}).
		Select("account_id").Where(idQueryCondition, userID).Take(&accountID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return "", status.Errorf(status.NotFound, "account not found: index lookup failed")
		}
		return "", status.NewGetAccountFromStoreError(result.Error)
	}

	return accountID, nil
}

// SaveUserLastLogin stores the last login time for a user in DB. It only writes when the stored value is unset or
// older than lastLogin, so repeating the same login doesn't rewrite the row and an older login never overwrites a newer one.
// It returns a NotFound error when the user doesn't exist.
func (s *SqlStore) SaveUserLastLogin(ctx context.Context, accountID, userID string, lastLogin time.Time) error {
	if lastLogin.IsZero() {
		return nil
	}

	result := s.db.Model(&types.User{}).
		Where(accountAndIDQueryCondition, accountID, userID).
		Where("last_login IS NULL OR last_login < ?", lastLogin).
		Update("last_login", lastLogin)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to save user last login: %s", result.Error)
		return status.Errorf(status.Internal, "failed to save user last login")
	}

	if result.RowsAffected == 0 {
		var count int64
		if err := s.db.Model(&types.User{}).Where(accountAndIDQueryCondition, accountID, userID).Count(&count).Error; err != nil {
			log.WithContext(ctx).Errorf("failed to check user existence: %s", err)
			return status.NewGetUserFromStoreError()
		}
		if count == 0 {
			return status.NewUserNotFoundError(userID)
		}
	}

	return nil
}

// GetUsersMissingEmailOrName returns non-service users with an empty email or name.
func (s *SqlStore) GetUsersMissingEmailOrName(ctx context.Context) ([]*types.User, error) {
	var users []*types.User
	result := s.db.Select("id", "account_id", "email", "name").
		Where("is_service_user = ?", false).
		Where("(COALESCE(email, '') = '' OR COALESCE(name, '') = '')").
		Find(&users)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get users missing email or name: %s", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get users missing email or name")
	}

	for _, user := range users {
		if err := user.DecryptSensitiveData(s.fieldEncrypt); err != nil {
			return nil, fmt.Errorf("decrypt user: %w", err)
		}
	}

	return users, nil
}

// FillUserEmailAndName sets the user's email and name only where they are empty.
func (s *SqlStore) FillUserEmailAndName(ctx context.Context, accountID, userID, email, name string) error {
	encrypted := &types.User{Email: email, Name: name}
	if err := encrypted.EncryptSensitiveData(s.fieldEncrypt); err != nil {
		return fmt.Errorf("encrypt user email and name: %w", err)
	}

	// SET expressions read the row as it was before the update.
	ifEmpty := func(field, column string, value any) clause.Expr {
		return gorm.Expr("CASE WHEN COALESCE("+field+", '') = '' THEN ? ELSE "+column+" END", value)
	}
	result := s.db.Model(&types.User{}).
		Where(accountAndIDQueryCondition, accountID, userID).
		Updates(map[string]any{
			"email":       gorm.Expr("COALESCE(NULLIF(email, ''), ?)", encrypted.Email),
			"name":        gorm.Expr("COALESCE(NULLIF(name, ''), ?)", encrypted.Name),
			"email_hash":  ifEmpty("email", "email_hash", encrypted.EmailHash),
			"name_hash_1": ifEmpty("name", "name_hash_1", encrypted.NameHash1),
			"name_hash_2": ifEmpty("name", "name_hash_2", encrypted.NameHash2),
			"name_hash_3": ifEmpty("name", "name_hash_3", encrypted.NameHash3),
		})
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to fill user email and name: %s", result.Error)
		return status.Errorf(status.Internal, "failed to fill user email and name")
	}

	return nil
}
