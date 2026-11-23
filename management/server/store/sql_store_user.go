package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"math"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
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
		return filters.AsConditions(tx, engine)
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

	toret := make([]*types.User, 0, len(users))
	for _, user := range users {
		if err := user.DecryptSensitiveData(s.fieldEncrypt); err != nil {
			return nil, 0, fmt.Errorf("decrypt user: %w", err)
		}
		if !strings.Contains(user.Name, filters.Name) {
			continue
		}
		toret = append(toret, user)
	}

	// the actual total count might be lower than reported by the query above due to false matches returned by the bloom filter
	// provided sufficiently long pattern is used (>= 5 chars), the number of false matches should be low, so we'll just report this number anyway
	return toret, int(count), nil
}

// UserFilters narrows the users GetAccountUsersPaginated lists. Empty fields don't filter.
type UserFilters struct {
	Name            string
	ServiceUser     *bool
	PendingApproval *bool
	Roles           []types.UserRole
	// GroupIDs matches users with any of these groups in their auto groups.
	GroupIDs []string
	UserIDs  []string
}

// AsConditions adds the filters to a users query.
func (f *UserFilters) AsConditions(db *gorm.DB, engine types.Engine) *gorm.DB {
	if engine == types.PostgresStoreEngine {
		db = fuzzyNameSearchConditionPostgres(db, f.Name)
	} else {
		db = fuzzyNameSearchConditionSqlite(db, f.Name)
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

func fuzzyNameSearchConditionPostgres(db *gorm.DB, pattern string) *gorm.DB {
	if pattern == "" {
		return db
	}

	b := newBloomFilter(160)
	for _, trigram := range toTrigrams(pattern) {
		b.add([]byte(trigram))
	}

	tx := db.Where("bitmap_to_bitarray(name_hash_1) @> bitmap_to_bitarray(?)", b.buckets[0])
	tx = tx.Where("bitmap_to_bitarray(name_hash_2) @> bitmap_to_bitarray(?)", b.buckets[1])
	tx = tx.Where("bitmap_to_bitarray(name_hash_3) @> bitmap_to_bitarray(?)", b.buckets[2])
	tx = tx.Where("bitmap_to_bitarray(name_hash_4) @> bitmap_to_bitarray(?)", b.buckets[3])
	tx = tx.Where("bitmap_to_bitarray(name_hash_5) @> bitmap_to_bitarray(?)", b.buckets[4])
	tx = tx.Where("bitmap_to_bitarray(name_hash_6) @> bitmap_to_bitarray(?)", b.buckets[5])

	return tx
}

func fuzzyNameSearchConditionSqlite(db *gorm.DB, pattern string) *gorm.DB {
	if pattern == "" {
		return db
	}

	tx := db
	b := newBloomFilter(160)
	for _, trigram := range toTrigrams(pattern) {
		b.add([]byte(trigram))
	}

	for i, bucket := range b.buckets {
		if bucket == 0 {
			continue
		}
		tx = tx.Where(fmt.Sprintf("name_hash_%d & ? = ?", i+1), bucket, bucket)
	}

	return tx
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

// use https://hur.st/bloomfilter/ to calculate filter params
type bloom struct {
	buckets  []int32
	k        uint64 // num of hash passes
	m        uint64 // num of bits
	nbuckets uint64 // bits split into 32bit words
}

func newBloomFilter(m int) *bloom {
	n := int(math.Ceil(float64(m) / 31))
	return &bloom{
		buckets:  make([]int32, n),
		m:        uint64(m),
		k:        4,
		nbuckets: uint64(n),
	}
}

func (b *bloom) add(d []byte) {
	h1, h2 := b.hash([]byte(d))
	for i := uint64(0); i < b.k; i++ {
		idx := (h1 + i*h2) % b.m
		bidx := idx % b.nbuckets
		bit := int32(1 << (idx % 31))
		b.buckets[bidx] |= bit
	}
}

func (b *bloom) test(d []string) bool {
	for _, trigram := range d {
		h1, h2 := b.hash([]byte(trigram))
		for i := uint64(0); i < b.k; i++ {
			idx := (h1 + i*h2) % b.m
			bidx := idx % b.nbuckets
			bit := int32(1 << (idx % 31))
			if b.buckets[bidx]&bit == 0 {
				return false
			}
		}
	}
	return true
}

func (b *bloom) hash(d []byte) (uint64, uint64) {
	h := fnv.New64a()
	h.Write(d)
	hash := h.Sum64()
	return uint64(hash & ((1 << 32) - 1)), uint64(hash >> 32)
}

func toTrigrams(s string) []string {
	in := strings.TrimSpace(s)
	if len(in) < 3 {
		return nil
	}

	parts := make([]string, 0)
	for _, part := range strings.Split(in, " ") {
		if len(part) < 3 {
			parts = append(parts, part+strings.Repeat(" ", 3-len(part)))
		} else {
			parts = append(parts, part)
		}
	}

	toret := make([]string, 0)
	for _, part := range parts {
		toret = append(toret, part[:3])
		for i := 3; i < len(part); i++ {
			toret = append(toret, part[i-2:i+1])
		}
	}
	return toret
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
