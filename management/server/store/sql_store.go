package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	log "github.com/sirupsen/logrus"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/internals/modules/zones"
	"github.com/netbirdio/netbird/management/internals/modules/zones/records"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	networkTypes "github.com/netbirdio/netbird/management/server/networks/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/management/server/util"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/status"
	"github.com/netbirdio/netbird/util/crypt"
)

const (
	storeSqliteFileName            = "store.db"
	idQueryCondition               = "id = ?"
	keyQueryCondition              = "key = ?"
	mysqlKeyQueryCondition         = "`key` = ?"
	accountAndIDQueryCondition     = "account_id = ? and id = ?"
	accountAndPeerIDQueryCondition = "account_id = ? and peer_id = ?"
	accountAndIDsQueryCondition    = "account_id = ? AND id IN ?"
	accountIDCondition             = "account_id = ?"
	peerNotFoundFMT                = "peer %s not found"

	pgMaxConnections    = 30
	pgMinConnections    = 1
	pgMaxConnLifetime   = 60 * time.Minute
	pgHealthCheckPeriod = 1 * time.Minute
)

// SqlStore represents an account storage backed by a Sql DB persisted to disk
type SqlStore struct {
	db                 *gorm.DB
	globalAccountLock  sync.Mutex
	metrics            telemetry.AppMetrics
	installationPK     int
	storeEngine        types.Engine
	pool               *pgxpool.Pool
	fieldEncrypt       *crypt.FieldEncrypt
	transactionTimeout time.Duration
}

type installation struct {
	ID                  uint `gorm:"primaryKey"`
	InstallationIDValue string
}

type migrationFunc func(*gorm.DB) error

// NewSqlStore creates a new SqlStore instance.
func NewSqlStore(ctx context.Context, db *gorm.DB, storeEngine types.Engine, metrics telemetry.AppMetrics, skipMigration bool) (*SqlStore, error) {
	sql, err := db.DB()
	if err != nil {
		return nil, err
	}

	conns, err := strconv.Atoi(os.Getenv("NB_SQL_MAX_OPEN_CONNS"))
	if err != nil {
		conns = runtime.NumCPU()
	}

	transactionTimeout := 5 * time.Minute
	if v := os.Getenv("NB_STORE_TRANSACTION_TIMEOUT"); v != "" {
		if parsed, err := time.ParseDuration(v); err == nil {
			transactionTimeout = parsed
		}
	}
	log.WithContext(ctx).Infof("Setting transaction timeout to %v", transactionTimeout)

	if storeEngine == types.SqliteStoreEngine {
		if err == nil {
			log.WithContext(ctx).Warnf("setting NB_SQL_MAX_OPEN_CONNS is not supported for sqlite, using default value 1")
		}
		conns = 1
	}

	sql.SetMaxOpenConns(conns)
	sql.SetMaxIdleConns(conns)
	sql.SetConnMaxLifetime(time.Hour)
	sql.SetConnMaxIdleTime(3 * time.Minute)

	log.WithContext(ctx).Infof("Set max open db connections to %d, max idle to %d, max lifetime to %v, max idle time to %v",
		conns, conns, time.Hour, 3*time.Minute)

	if skipMigration {
		log.WithContext(ctx).Infof("skipping migration")
		return &SqlStore{db: db, storeEngine: storeEngine, metrics: metrics, installationPK: 1, transactionTimeout: transactionTimeout}, nil
	}

	if err := migratePreAuto(ctx, db); err != nil {
		return nil, fmt.Errorf("migratePreAuto: %w", err)
	}
	err = db.AutoMigrate(
		&types.SetupKey{}, &nbpeer.Peer{}, &types.User{}, &types.PersonalAccessToken{}, &types.Group{}, &types.GroupPeer{},
		&types.Account{}, &types.Policy{}, &types.PolicyRule{}, &route.Route{}, &nbdns.NameServerGroup{},
		&installation{}, &types.ExtraSettings{}, &posture.Checks{}, &nbpeer.NetworkAddress{},
		&networkTypes.Network{}, &routerTypes.NetworkRouter{}, &resourceTypes.NetworkResource{}, &types.AccountOnboarding{},
		&types.Job{}, &zones.Zone{}, &records.Record{}, &types.UserInviteRecord{},
	)
	if err != nil {
		return nil, fmt.Errorf("auto migratePreAuto: %w", err)
	}
	if err := migratePostAuto(ctx, db); err != nil {
		return nil, fmt.Errorf("migratePostAuto: %w", err)
	}

	return &SqlStore{db: db, storeEngine: storeEngine, metrics: metrics, installationPK: 1, transactionTimeout: transactionTimeout}, nil
}

func GetKeyQueryCondition(s *SqlStore) string {
	if s.storeEngine == types.MysqlStoreEngine {
		return mysqlKeyQueryCondition
	}
	return keyQueryCondition
}

// SaveJob persists a job in DB
func (s *SqlStore) CreatePeerJob(ctx context.Context, job *types.Job) error {
	result := s.db.Create(job)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to create job in store: %s", result.Error)
		return status.Errorf(status.Internal, "failed to create job in store")
	}
	return nil
}

func (s *SqlStore) CompletePeerJob(ctx context.Context, job *types.Job) error {
	result := s.db.
		Model(&types.Job{}).
		Where(idQueryCondition, job.ID).
		Updates(job)

	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to update job in store: %s", result.Error)
		return status.Errorf(status.Internal, "failed to update job in store")
	}
	return nil
}

// job was pending for too long and has been cancelled
func (s *SqlStore) MarkPendingJobsAsFailed(ctx context.Context, accountID, peerID, jobID, reason string) error {
	now := time.Now().UTC()
	result := s.db.
		Model(&types.Job{}).
		Where(accountAndPeerIDQueryCondition+" AND id = ?"+" AND status = ?", accountID, peerID, jobID, types.JobStatusPending).
		Updates(types.Job{
			Status:       types.JobStatusFailed,
			FailedReason: reason,
			CompletedAt:  &now,
		})
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to mark pending jobs as Failed job in store: %s", result.Error)
		return status.Errorf(status.Internal, "failed to mark pending job as Failed in store")
	}
	return nil
}

// job was pending for too long and has been cancelled
func (s *SqlStore) MarkAllPendingJobsAsFailed(ctx context.Context, accountID, peerID, reason string) error {
	now := time.Now().UTC()
	result := s.db.
		Model(&types.Job{}).
		Where(accountAndPeerIDQueryCondition+" AND status = ?", accountID, peerID, types.JobStatusPending).
		Updates(types.Job{
			Status:       types.JobStatusFailed,
			FailedReason: reason,
			CompletedAt:  &now,
		})
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to mark pending jobs as Failed job in store: %s", result.Error)
		return status.Errorf(status.Internal, "failed to mark pending job as Failed in store")
	}
	return nil
}

// GetJobByID fetches job by ID
func (s *SqlStore) GetPeerJobByID(ctx context.Context, accountID, jobID string) (*types.Job, error) {
	var job types.Job
	err := s.db.
		Where(accountAndIDQueryCondition, accountID, jobID).
		First(&job).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, status.Errorf(status.NotFound, "job %s not found", jobID)
	}
	if err != nil {
		log.WithContext(ctx).Errorf("failed to fetch job from store: %s", err)
		return nil, err
	}
	return &job, nil
}

// get all jobs
func (s *SqlStore) GetPeerJobs(ctx context.Context, accountID, peerID string) ([]*types.Job, error) {
	var jobs []*types.Job
	err := s.db.
		Where(accountAndPeerIDQueryCondition, accountID, peerID).
		Order("created_at DESC").
		Find(&jobs).Error

	if err != nil {
		log.WithContext(ctx).Errorf("failed to fetch jobs from store: %s", err)
		return nil, err
	}

	return jobs, nil
}

// AcquireGlobalLock acquires global lock across all the accounts and returns a function that releases the lock
func (s *SqlStore) AcquireGlobalLock(ctx context.Context) (unlock func()) {
	log.WithContext(ctx).Tracef("acquiring global lock")
	start := time.Now()
	s.globalAccountLock.Lock()

	unlock = func() {
		s.globalAccountLock.Unlock()
		log.WithContext(ctx).Tracef("released global lock in %v", time.Since(start))
	}

	took := time.Since(start)
	log.WithContext(ctx).Tracef("took %v to acquire global lock", took)
	if s.metrics != nil {
		s.metrics.StoreMetrics().CountGlobalLockAcquisitionDuration(took)
	}

	return unlock
}

// Deprecated: Full account operations are no longer supported
func (s *SqlStore) SaveAccount(ctx context.Context, account *types.Account) error {
	start := time.Now()
	defer func() {
		elapsed := time.Since(start)
		if elapsed > 1*time.Second {
			log.WithContext(ctx).Tracef("SaveAccount for account %s exceeded 1s, took: %v", account.Id, elapsed)
		}
	}()

	// todo: remove this check after the issue is resolved
	s.checkAccountDomainBeforeSave(ctx, account.Id, account.Domain)

	generateAccountSQLTypes(account)

	// Encrypt sensitive user data before saving
	for i := range account.UsersG {
		if err := account.UsersG[i].EncryptSensitiveData(s.fieldEncrypt); err != nil {
			return fmt.Errorf("encrypt user: %w", err)
		}
	}

	for _, group := range account.GroupsG {
		group.StoreGroupPeers()
	}

	err := s.transaction(func(tx *gorm.DB) error {
		result := tx.Select(clause.Associations).Delete(account.Policies, "account_id = ?", account.Id)
		if result.Error != nil {
			return result.Error
		}

		result = tx.Select(clause.Associations).Delete(account.UsersG, "account_id = ?", account.Id)
		if result.Error != nil {
			return result.Error
		}

		result = tx.Select(clause.Associations).Delete(account)
		if result.Error != nil {
			return result.Error
		}

		result = tx.
			Session(&gorm.Session{FullSaveAssociations: true}).
			Clauses(clause.OnConflict{UpdateAll: true}).
			Create(account)
		if result.Error != nil {
			return result.Error
		}
		return nil
	})

	took := time.Since(start)
	if s.metrics != nil {
		s.metrics.StoreMetrics().CountPersistenceDuration(took)
	}
	log.WithContext(ctx).Debugf("took %d ms to persist an account to the store", took.Milliseconds())

	return err
}

// generateAccountSQLTypes generates the GORM compatible types for the account
func generateAccountSQLTypes(account *types.Account) {
	for _, key := range account.SetupKeys {
		account.SetupKeysG = append(account.SetupKeysG, *key)
	}

	if len(account.SetupKeys) != len(account.SetupKeysG) {
		log.Warnf("SetupKeysG length mismatch for account %s", account.Id)
	}

	for id, peer := range account.Peers {
		peer.ID = id
		account.PeersG = append(account.PeersG, *peer)
	}

	for id, user := range account.Users {
		user.Id = id
		for id, pat := range user.PATs {
			pat.ID = id
			user.PATsG = append(user.PATsG, *pat)
		}
		account.UsersG = append(account.UsersG, *user)
	}

	for id, group := range account.Groups {
		group.ID = id
		group.AccountID = account.Id
		account.GroupsG = append(account.GroupsG, group)
	}

	for id, route := range account.Routes {
		route.ID = id
		account.RoutesG = append(account.RoutesG, *route)
	}

	for id, ns := range account.NameServerGroups {
		ns.ID = id
		account.NameServerGroupsG = append(account.NameServerGroupsG, *ns)
	}
}

// checkAccountDomainBeforeSave temporary method to troubleshoot an issue with domains getting blank
func (s *SqlStore) checkAccountDomainBeforeSave(ctx context.Context, accountID, newDomain string) {
	var acc types.Account
	var domain string
	result := s.db.Model(&acc).Select("domain").Where(idQueryCondition, accountID).Take(&domain)
	if result.Error != nil {
		if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
			log.WithContext(ctx).Errorf("error when getting account %s from the store to check domain: %s", accountID, result.Error)
		}
		return
	}
	if domain != "" && newDomain == "" {
		log.WithContext(ctx).Warnf("saving an account with empty domain when there was a domain set. Previous domain %s, Account ID: %s, Trace: %s", domain, accountID, debug.Stack())
	}
}

func (s *SqlStore) DeleteAccount(ctx context.Context, account *types.Account) error {
	start := time.Now()

	err := s.transaction(func(tx *gorm.DB) error {
		result := tx.Select(clause.Associations).Delete(account.Policies, "account_id = ?", account.Id)
		if result.Error != nil {
			return result.Error
		}

		result = tx.Select(clause.Associations).Delete(account.UsersG, "account_id = ?", account.Id)
		if result.Error != nil {
			return result.Error
		}

		result = tx.Select(clause.Associations).Delete(account)
		if result.Error != nil {
			return result.Error
		}

		return nil
	})

	took := time.Since(start)
	if s.metrics != nil {
		s.metrics.StoreMetrics().CountPersistenceDuration(took)
	}
	log.WithContext(ctx).Tracef("took %d ms to delete an account to the store", took.Milliseconds())

	return err
}

func (s *SqlStore) SaveInstallationID(_ context.Context, ID string) error {
	installation := installation{InstallationIDValue: ID}
	installation.ID = uint(s.installationPK)

	return s.db.Clauses(clause.OnConflict{UpdateAll: true}).Create(&installation).Error
}

func (s *SqlStore) GetInstallationID() string {
	var installation installation

	if result := s.db.Take(&installation, idQueryCondition, s.installationPK); result.Error != nil {
		return ""
	}

	return installation.InstallationIDValue
}

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

func (s *SqlStore) UpdateAccountDomainAttributes(ctx context.Context, accountID string, domain string, category string, isPrimaryDomain bool) error {
	accountCopy := types.Account{
		Domain:                 domain,
		DomainCategory:         category,
		IsDomainPrimaryAccount: isPrimaryDomain,
	}

	fieldsToUpdate := []string{"domain", "domain_category", "is_domain_primary_account"}
	result := s.db.Model(&types.Account{}).
		Select(fieldsToUpdate).
		Where(idQueryCondition, accountID).
		Updates(&accountCopy)
	if result.Error != nil {
		return status.Errorf(status.Internal, "failed to update account domain attributes to store: %v", result.Error)
	}

	if result.RowsAffected == 0 {
		return status.Errorf(status.NotFound, "account %s", accountID)
	}

	return nil
}

func (s *SqlStore) SavePeerStatus(ctx context.Context, accountID, peerID string, peerStatus nbpeer.PeerStatus) error {
	var peerCopy nbpeer.Peer
	peerCopy.Status = &peerStatus

	fieldsToUpdate := []string{
		"peer_status_last_seen", "peer_status_connected",
		"peer_status_login_expired", "peer_status_required_approval",
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

func (s *SqlStore) SavePeerLocation(ctx context.Context, accountID string, peerWithLocation *nbpeer.Peer) error {
	// To maintain data integrity, we create a copy of the peer's location to prevent unintended updates to other fields.
	var peerCopy nbpeer.Peer
	// Since the location field has been migrated to JSON serialization,
	// updating the struct ensures the correct data format is inserted into the database.
	peerCopy.Location = peerWithLocation.Location

	result := s.db.Model(&nbpeer.Peer{}).
		Where(accountAndIDQueryCondition, accountID, peerWithLocation.ID).
		Updates(peerCopy)

	if result.Error != nil {
		return status.Errorf(status.Internal, "failed to save peer locations to store: %v", result.Error)
	}

	if result.RowsAffected == 0 {
		return status.Errorf(status.NotFound, peerNotFoundFMT, peerWithLocation.ID)
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

// CreateGroups creates the given list of groups to the database.
func (s *SqlStore) CreateGroups(ctx context.Context, accountID string, groups []*types.Group) error {
	if len(groups) == 0 {
		return nil
	}

	return s.db.Transaction(func(tx *gorm.DB) error {
		result := tx.
			Clauses(
				clause.OnConflict{
					Where:     clause.Where{Exprs: []clause.Expression{clause.Eq{Column: "groups.account_id", Value: accountID}}},
					UpdateAll: true,
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
					Where:     clause.Where{Exprs: []clause.Expression{clause.Eq{Column: "groups.account_id", Value: accountID}}},
					UpdateAll: true,
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

// DeleteHashedPAT2TokenIDIndex is noop in SqlStore
func (s *SqlStore) DeleteHashedPAT2TokenIDIndex(hashedToken string) error {
	return nil
}

// DeleteTokenID2UserIDIndex is noop in SqlStore
func (s *SqlStore) DeleteTokenID2UserIDIndex(tokenID string) error {
	return nil
}

func (s *SqlStore) GetAccountByPrivateDomain(ctx context.Context, domain string) (*types.Account, error) {
	accountID, err := s.GetAccountIDByPrivateDomain(ctx, LockingStrengthNone, domain)
	if err != nil {
		return nil, err
	}

	// TODO:  rework to not call GetAccount
	return s.GetAccount(ctx, accountID)
}

func (s *SqlStore) GetAccountIDByPrivateDomain(ctx context.Context, lockStrength LockingStrength, domain string) (string, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var accountID string
	result := tx.Model(&types.Account{}).Select("id").
		Where("domain = ? and is_domain_primary_account = ? and domain_category = ?",
			strings.ToLower(domain), true, types.PrivateCategory,
		).Take(&accountID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return "", status.Errorf(status.NotFound, "account not found: provided domain is not registered or is not private")
		}
		log.WithContext(ctx).Errorf("error when getting account from the store: %s", result.Error)
		return "", status.NewGetAccountFromStoreError(result.Error)
	}

	return accountID, nil
}

func (s *SqlStore) GetAccountBySetupKey(ctx context.Context, setupKey string) (*types.Account, error) {
	var key types.SetupKey
	result := s.db.Select("account_id").Take(&key, GetKeyQueryCondition(s), setupKey)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.NewSetupKeyNotFoundError(setupKey)
		}
		log.WithContext(ctx).Errorf("failed to get account by setup key from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get account by setup key from store")
	}

	if key.AccountID == "" {
		return nil, status.Errorf(status.NotFound, "account not found: index lookup failed")
	}

	return s.GetAccount(ctx, key.AccountID)
}

func (s *SqlStore) GetTokenIDByHashedToken(ctx context.Context, hashedToken string) (string, error) {
	var token types.PersonalAccessToken
	result := s.db.Take(&token, "hashed_token = ?", hashedToken)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return "", status.Errorf(status.NotFound, "account not found: index lookup failed")
		}
		log.WithContext(ctx).Errorf("error when getting token from the store: %s", result.Error)
		return "", status.NewGetAccountFromStoreError(result.Error)
	}

	return token.ID, nil
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
	err := s.transaction(func(tx *gorm.DB) error {
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

// SaveUserInvite saves a user invite to the database
func (s *SqlStore) SaveUserInvite(ctx context.Context, invite *types.UserInviteRecord) error {
	inviteCopy := invite.Copy()
	if err := inviteCopy.EncryptSensitiveData(s.fieldEncrypt); err != nil {
		return fmt.Errorf("encrypt invite: %w", err)
	}

	result := s.db.Save(inviteCopy)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to save user invite to store: %s", result.Error)
		return status.Errorf(status.Internal, "failed to save user invite to store")
	}
	return nil
}

// GetUserInviteByID retrieves a user invite by its ID and account ID
func (s *SqlStore) GetUserInviteByID(ctx context.Context, lockStrength LockingStrength, accountID, inviteID string) (*types.UserInviteRecord, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var invite types.UserInviteRecord
	result := tx.Where("account_id = ?", accountID).Take(&invite, idQueryCondition, inviteID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(status.NotFound, "user invite not found")
		}
		log.WithContext(ctx).Errorf("failed to get user invite from store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get user invite from store")
	}

	if err := invite.DecryptSensitiveData(s.fieldEncrypt); err != nil {
		return nil, fmt.Errorf("decrypt invite: %w", err)
	}

	return &invite, nil
}

// GetUserInviteByHashedToken retrieves a user invite by its hashed token
func (s *SqlStore) GetUserInviteByHashedToken(ctx context.Context, lockStrength LockingStrength, hashedToken string) (*types.UserInviteRecord, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var invite types.UserInviteRecord
	result := tx.Take(&invite, "hashed_token = ?", hashedToken)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(status.NotFound, "user invite not found")
		}
		log.WithContext(ctx).Errorf("failed to get user invite from store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get user invite from store")
	}

	if err := invite.DecryptSensitiveData(s.fieldEncrypt); err != nil {
		return nil, fmt.Errorf("decrypt invite: %w", err)
	}

	return &invite, nil
}

// GetUserInviteByEmail retrieves a user invite by account ID and email.
// Since email is encrypted with random IVs, we fetch all invites for the account
// and compare emails in memory after decryption.
func (s *SqlStore) GetUserInviteByEmail(ctx context.Context, lockStrength LockingStrength, accountID, email string) (*types.UserInviteRecord, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var invites []*types.UserInviteRecord
	result := tx.Find(&invites, "account_id = ?", accountID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get user invites from store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get user invites from store")
	}

	for _, invite := range invites {
		if err := invite.DecryptSensitiveData(s.fieldEncrypt); err != nil {
			return nil, fmt.Errorf("decrypt invite: %w", err)
		}
		if strings.EqualFold(invite.Email, email) {
			return invite, nil
		}
	}

	return nil, status.Errorf(status.NotFound, "user invite not found for email")
}

// GetAccountUserInvites retrieves all user invites for an account
func (s *SqlStore) GetAccountUserInvites(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*types.UserInviteRecord, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var invites []*types.UserInviteRecord
	result := tx.Find(&invites, "account_id = ?", accountID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get user invites from store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get user invites from store")
	}

	for _, invite := range invites {
		if err := invite.DecryptSensitiveData(s.fieldEncrypt); err != nil {
			return nil, fmt.Errorf("decrypt invite: %w", err)
		}
	}

	return invites, nil
}

// DeleteUserInvite deletes a user invite by its ID
func (s *SqlStore) DeleteUserInvite(ctx context.Context, inviteID string) error {
	result := s.db.Delete(&types.UserInviteRecord{}, idQueryCondition, inviteID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to delete user invite from store: %s", result.Error)
		return status.Errorf(status.Internal, "failed to delete user invite from store")
	}
	return nil
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

func (s *SqlStore) GetAccountsCounter(ctx context.Context) (int64, error) {
	var count int64
	result := s.db.Model(&types.Account{}).Count(&count)
	if result.Error != nil {
		return 0, fmt.Errorf("failed to get all accounts counter: %w", result.Error)
	}

	return count, nil
}

func (s *SqlStore) GetAllAccounts(ctx context.Context) (all []*types.Account) {
	var accounts []types.Account
	result := s.db.Find(&accounts)
	if result.Error != nil {
		return all
	}

	for _, account := range accounts {
		if acc, err := s.GetAccount(ctx, account.Id); err == nil {
			all = append(all, acc)
		}
	}

	return all
}

func (s *SqlStore) GetAccountMeta(ctx context.Context, lockStrength LockingStrength, accountID string) (*types.AccountMeta, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var accountMeta types.AccountMeta
	result := tx.Model(&types.Account{}).
		Take(&accountMeta, idQueryCondition, accountID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("error when getting account meta %s from the store: %s", accountID, result.Error)
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.NewAccountNotFoundError(accountID)
		}
		return nil, status.NewGetAccountFromStoreError(result.Error)
	}

	return &accountMeta, nil
}

// GetAccountOnboarding retrieves the onboarding information for a specific account.
func (s *SqlStore) GetAccountOnboarding(ctx context.Context, accountID string) (*types.AccountOnboarding, error) {
	var accountOnboarding types.AccountOnboarding
	result := s.db.Model(&accountOnboarding).Take(&accountOnboarding, accountIDCondition, accountID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.NewAccountOnboardingNotFoundError(accountID)
		}
		log.WithContext(ctx).Errorf("error when getting account onboarding %s from the store: %s", accountID, result.Error)
		return nil, status.NewGetAccountFromStoreError(result.Error)
	}

	return &accountOnboarding, nil
}

// SaveAccountOnboarding updates the onboarding information for a specific account.
func (s *SqlStore) SaveAccountOnboarding(ctx context.Context, onboarding *types.AccountOnboarding) error {
	result := s.db.Clauses(clause.OnConflict{UpdateAll: true}).Create(onboarding)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("error when saving account onboarding %s in the store: %s", onboarding.AccountID, result.Error)
		return status.Errorf(status.Internal, "error when saving account onboarding %s in the store: %s", onboarding.AccountID, result.Error)
	}

	return nil
}

func (s *SqlStore) GetAccount(ctx context.Context, accountID string) (*types.Account, error) {
	if s.pool != nil {
		return s.getAccountPgx(ctx, accountID)
	}
	return s.getAccountGorm(ctx, accountID)
}

func (s *SqlStore) getAccountGorm(ctx context.Context, accountID string) (*types.Account, error) {
	start := time.Now()
	defer func() {
		elapsed := time.Since(start)
		if elapsed > 1*time.Second {
			log.WithContext(ctx).Tracef("GetAccount for account %s exceeded 1s, took: %v", accountID, elapsed)
		}
	}()

	var account types.Account
	result := s.db.Model(&account).
		Preload("UsersG.PATsG"). // have to be specified as this is nested reference
		Preload("Policies.Rules").
		Preload("SetupKeysG").
		Preload("PeersG").
		Preload("UsersG").
		Preload("GroupsG.GroupPeers").
		Preload("RoutesG").
		Preload("NameServerGroupsG").
		Preload("PostureChecks").
		Preload("Networks").
		Preload("NetworkRouters").
		Preload("NetworkResources").
		Preload("Onboarding").
		Take(&account, idQueryCondition, accountID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("error when getting account %s from the store: %s", accountID, result.Error)
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.NewAccountNotFoundError(accountID)
		}
		return nil, status.NewGetAccountFromStoreError(result.Error)
	}

	account.SetupKeys = make(map[string]*types.SetupKey, len(account.SetupKeysG))
	for _, key := range account.SetupKeysG {
		if key.UpdatedAt.IsZero() {
			key.UpdatedAt = key.CreatedAt
		}
		if key.AutoGroups == nil {
			key.AutoGroups = []string{}
		}
		account.SetupKeys[key.Key] = &key
	}
	account.SetupKeysG = nil

	account.Peers = make(map[string]*nbpeer.Peer, len(account.PeersG))
	for _, peer := range account.PeersG {
		account.Peers[peer.ID] = &peer
	}
	account.PeersG = nil
	account.Users = make(map[string]*types.User, len(account.UsersG))
	for _, user := range account.UsersG {
		user.PATs = make(map[string]*types.PersonalAccessToken, len(user.PATs))
		for _, pat := range user.PATsG {
			pat.UserID = ""
			user.PATs[pat.ID] = &pat
		}
		if user.AutoGroups == nil {
			user.AutoGroups = []string{}
		}
		if err := user.DecryptSensitiveData(s.fieldEncrypt); err != nil {
			return nil, fmt.Errorf("decrypt user: %w", err)
		}
		account.Users[user.Id] = &user
		user.PATsG = nil
	}
	account.UsersG = nil
	account.Groups = make(map[string]*types.Group, len(account.GroupsG))
	for _, group := range account.GroupsG {
		group.Peers = make([]string, len(group.GroupPeers))
		for i, gp := range group.GroupPeers {
			group.Peers[i] = gp.PeerID
		}
		if group.Resources == nil {
			group.Resources = []types.Resource{}
		}
		account.Groups[group.ID] = group
	}
	account.GroupsG = nil

	account.Routes = make(map[route.ID]*route.Route, len(account.RoutesG))
	for _, route := range account.RoutesG {
		account.Routes[route.ID] = &route
	}
	account.RoutesG = nil
	account.NameServerGroups = make(map[string]*nbdns.NameServerGroup, len(account.NameServerGroupsG))
	for _, ns := range account.NameServerGroupsG {
		ns.AccountID = ""
		if ns.NameServers == nil {
			ns.NameServers = []nbdns.NameServer{}
		}
		if ns.Groups == nil {
			ns.Groups = []string{}
		}
		if ns.Domains == nil {
			ns.Domains = []string{}
		}
		account.NameServerGroups[ns.ID] = &ns
	}
	account.NameServerGroupsG = nil
	account.InitOnce()
	return &account, nil
}

func (s *SqlStore) getAccountPgx(ctx context.Context, accountID string) (*types.Account, error) {
	account, err := s.getAccount(ctx, accountID)
	if err != nil {
		return nil, err
	}

	var wg sync.WaitGroup
	errChan := make(chan error, 12)

	wg.Add(1)
	go func() {
		defer wg.Done()
		keys, err := s.getSetupKeys(ctx, accountID)
		if err != nil {
			errChan <- err
			return
		}
		account.SetupKeysG = keys
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		peers, err := s.getPeers(ctx, accountID)
		if err != nil {
			errChan <- err
			return
		}
		account.PeersG = peers
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		users, err := s.getUsers(ctx, accountID)
		if err != nil {
			errChan <- err
			return
		}
		account.UsersG = users
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		groups, err := s.getGroups(ctx, accountID)
		if err != nil {
			errChan <- err
			return
		}
		account.GroupsG = groups
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		policies, err := s.getPolicies(ctx, accountID)
		if err != nil {
			errChan <- err
			return
		}
		account.Policies = policies
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		routes, err := s.getRoutes(ctx, accountID)
		if err != nil {
			errChan <- err
			return
		}
		account.RoutesG = routes
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		nsgs, err := s.getNameServerGroups(ctx, accountID)
		if err != nil {
			errChan <- err
			return
		}
		account.NameServerGroupsG = nsgs
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		checks, err := s.getPostureChecks(ctx, accountID)
		if err != nil {
			errChan <- err
			return
		}
		account.PostureChecks = checks
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		networks, err := s.getNetworks(ctx, accountID)
		if err != nil {
			errChan <- err
			return
		}
		account.Networks = networks
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		routers, err := s.getNetworkRouters(ctx, accountID)
		if err != nil {
			errChan <- err
			return
		}
		account.NetworkRouters = routers
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		resources, err := s.getNetworkResources(ctx, accountID)
		if err != nil {
			errChan <- err
			return
		}
		account.NetworkResources = resources
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		err := s.getAccountOnboarding(ctx, accountID, account)
		if err != nil {
			errChan <- err
			return
		}
	}()

	wg.Wait()
	close(errChan)
	for e := range errChan {
		if e != nil {
			return nil, e
		}
	}

	var userIDs []string
	for _, u := range account.UsersG {
		userIDs = append(userIDs, u.Id)
	}
	var policyIDs []string
	for _, p := range account.Policies {
		policyIDs = append(policyIDs, p.ID)
	}
	var groupIDs []string
	for _, g := range account.GroupsG {
		groupIDs = append(groupIDs, g.ID)
	}

	wg.Add(3)
	errChan = make(chan error, 3)

	var pats []types.PersonalAccessToken
	go func() {
		defer wg.Done()
		var err error
		pats, err = s.getPersonalAccessTokens(ctx, userIDs)
		if err != nil {
			errChan <- err
		}
	}()

	var rules []*types.PolicyRule
	go func() {
		defer wg.Done()
		var err error
		rules, err = s.getPolicyRules(ctx, policyIDs)
		if err != nil {
			errChan <- err
		}
	}()

	var groupPeers []types.GroupPeer
	go func() {
		defer wg.Done()
		var err error
		groupPeers, err = s.getGroupPeers(ctx, groupIDs)
		if err != nil {
			errChan <- err
		}
	}()

	wg.Wait()
	close(errChan)
	for e := range errChan {
		if e != nil {
			return nil, e
		}
	}

	patsByUserID := make(map[string][]*types.PersonalAccessToken)
	for i := range pats {
		pat := &pats[i]
		patsByUserID[pat.UserID] = append(patsByUserID[pat.UserID], pat)
		pat.UserID = ""
	}

	rulesByPolicyID := make(map[string][]*types.PolicyRule)
	for _, rule := range rules {
		rulesByPolicyID[rule.PolicyID] = append(rulesByPolicyID[rule.PolicyID], rule)
	}

	peersByGroupID := make(map[string][]string)
	for _, gp := range groupPeers {
		peersByGroupID[gp.GroupID] = append(peersByGroupID[gp.GroupID], gp.PeerID)
	}

	account.SetupKeys = make(map[string]*types.SetupKey, len(account.SetupKeysG))
	for i := range account.SetupKeysG {
		key := &account.SetupKeysG[i]
		account.SetupKeys[key.Key] = key
	}

	account.Peers = make(map[string]*nbpeer.Peer, len(account.PeersG))
	for i := range account.PeersG {
		peer := &account.PeersG[i]
		account.Peers[peer.ID] = peer
	}

	account.Users = make(map[string]*types.User, len(account.UsersG))
	for i := range account.UsersG {
		user := &account.UsersG[i]
		if err := user.DecryptSensitiveData(s.fieldEncrypt); err != nil {
			return nil, fmt.Errorf("decrypt user: %w", err)
		}
		user.PATs = make(map[string]*types.PersonalAccessToken)
		if userPats, ok := patsByUserID[user.Id]; ok {
			for j := range userPats {
				pat := userPats[j]
				user.PATs[pat.ID] = pat
			}
		}
		account.Users[user.Id] = user
	}

	for i := range account.Policies {
		policy := account.Policies[i]
		if policyRules, ok := rulesByPolicyID[policy.ID]; ok {
			policy.Rules = policyRules
		}
	}

	account.Groups = make(map[string]*types.Group, len(account.GroupsG))
	for i := range account.GroupsG {
		group := account.GroupsG[i]
		if peerIDs, ok := peersByGroupID[group.ID]; ok {
			group.Peers = peerIDs
		}
		account.Groups[group.ID] = group
	}

	account.Routes = make(map[route.ID]*route.Route, len(account.RoutesG))
	for i := range account.RoutesG {
		route := &account.RoutesG[i]
		account.Routes[route.ID] = route
	}

	account.NameServerGroups = make(map[string]*nbdns.NameServerGroup, len(account.NameServerGroupsG))
	for i := range account.NameServerGroupsG {
		nsg := &account.NameServerGroupsG[i]
		nsg.AccountID = ""
		account.NameServerGroups[nsg.ID] = nsg
	}

	account.SetupKeysG = nil
	account.PeersG = nil
	account.UsersG = nil
	account.GroupsG = nil
	account.RoutesG = nil
	account.NameServerGroupsG = nil

	return account, nil
}

func (s *SqlStore) getAccount(ctx context.Context, accountID string) (*types.Account, error) {
	var account types.Account
	account.Network = &types.Network{}
	const accountQuery = `
		SELECT
			id, created_by, created_at, domain, domain_category, is_domain_primary_account,
			-- Embedded Network
			network_identifier, network_net, network_dns, network_serial,
			-- Embedded DNSSettings
			dns_settings_disabled_management_groups,
			-- Embedded Settings
			settings_peer_login_expiration_enabled, settings_peer_login_expiration,
			settings_peer_inactivity_expiration_enabled, settings_peer_inactivity_expiration,
			settings_regular_users_view_blocked, settings_groups_propagation_enabled,
			settings_jwt_groups_enabled, settings_jwt_groups_claim_name, settings_jwt_allow_groups,
			settings_routing_peer_dns_resolution_enabled, settings_dns_domain, settings_network_range,
			settings_lazy_connection_enabled,
			-- Embedded ExtraSettings
			settings_extra_peer_approval_enabled, settings_extra_user_approval_required,
			settings_extra_integrated_validator, settings_extra_integrated_validator_groups
		FROM accounts WHERE id = $1`

	var (
		sPeerLoginExpirationEnabled      sql.NullBool
		sPeerLoginExpiration             sql.NullInt64
		sPeerInactivityExpirationEnabled sql.NullBool
		sPeerInactivityExpiration        sql.NullInt64
		sRegularUsersViewBlocked         sql.NullBool
		sGroupsPropagationEnabled        sql.NullBool
		sJWTGroupsEnabled                sql.NullBool
		sJWTGroupsClaimName              sql.NullString
		sJWTAllowGroups                  sql.NullString
		sRoutingPeerDNSResolutionEnabled sql.NullBool
		sDNSDomain                       sql.NullString
		sNetworkRange                    sql.NullString
		sLazyConnectionEnabled           sql.NullBool
		sExtraPeerApprovalEnabled        sql.NullBool
		sExtraUserApprovalRequired       sql.NullBool
		sExtraIntegratedValidator        sql.NullString
		sExtraIntegratedValidatorGroups  sql.NullString
		networkNet                       sql.NullString
		dnsSettingsDisabledGroups        sql.NullString
		networkIdentifier                sql.NullString
		networkDns                       sql.NullString
		networkSerial                    sql.NullInt64
		createdAt                        sql.NullTime
	)
	err := s.pool.QueryRow(ctx, accountQuery, accountID).Scan(
		&account.Id, &account.CreatedBy, &createdAt, &account.Domain, &account.DomainCategory, &account.IsDomainPrimaryAccount,
		&networkIdentifier, &networkNet, &networkDns, &networkSerial,
		&dnsSettingsDisabledGroups,
		&sPeerLoginExpirationEnabled, &sPeerLoginExpiration,
		&sPeerInactivityExpirationEnabled, &sPeerInactivityExpiration,
		&sRegularUsersViewBlocked, &sGroupsPropagationEnabled,
		&sJWTGroupsEnabled, &sJWTGroupsClaimName, &sJWTAllowGroups,
		&sRoutingPeerDNSResolutionEnabled, &sDNSDomain, &sNetworkRange,
		&sLazyConnectionEnabled,
		&sExtraPeerApprovalEnabled, &sExtraUserApprovalRequired,
		&sExtraIntegratedValidator, &sExtraIntegratedValidatorGroups,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, status.NewAccountNotFoundError(accountID)
		}
		return nil, status.NewGetAccountFromStoreError(err)
	}

	account.Settings = &types.Settings{Extra: &types.ExtraSettings{}}
	if networkNet.Valid {
		_ = json.Unmarshal([]byte(networkNet.String), &account.Network.Net)
	}
	if createdAt.Valid {
		account.CreatedAt = createdAt.Time
	}
	if dnsSettingsDisabledGroups.Valid {
		_ = json.Unmarshal([]byte(dnsSettingsDisabledGroups.String), &account.DNSSettings.DisabledManagementGroups)
	}
	if networkIdentifier.Valid {
		account.Network.Identifier = networkIdentifier.String
	}
	if networkDns.Valid {
		account.Network.Dns = networkDns.String
	}
	if networkSerial.Valid {
		account.Network.Serial = uint64(networkSerial.Int64)
	}
	if sPeerLoginExpirationEnabled.Valid {
		account.Settings.PeerLoginExpirationEnabled = sPeerLoginExpirationEnabled.Bool
	}
	if sPeerLoginExpiration.Valid {
		account.Settings.PeerLoginExpiration = time.Duration(sPeerLoginExpiration.Int64)
	}
	if sPeerInactivityExpirationEnabled.Valid {
		account.Settings.PeerInactivityExpirationEnabled = sPeerInactivityExpirationEnabled.Bool
	}
	if sPeerInactivityExpiration.Valid {
		account.Settings.PeerInactivityExpiration = time.Duration(sPeerInactivityExpiration.Int64)
	}
	if sRegularUsersViewBlocked.Valid {
		account.Settings.RegularUsersViewBlocked = sRegularUsersViewBlocked.Bool
	}
	if sGroupsPropagationEnabled.Valid {
		account.Settings.GroupsPropagationEnabled = sGroupsPropagationEnabled.Bool
	}
	if sJWTGroupsEnabled.Valid {
		account.Settings.JWTGroupsEnabled = sJWTGroupsEnabled.Bool
	}
	if sJWTGroupsClaimName.Valid {
		account.Settings.JWTGroupsClaimName = sJWTGroupsClaimName.String
	}
	if sRoutingPeerDNSResolutionEnabled.Valid {
		account.Settings.RoutingPeerDNSResolutionEnabled = sRoutingPeerDNSResolutionEnabled.Bool
	}
	if sDNSDomain.Valid {
		account.Settings.DNSDomain = sDNSDomain.String
	}
	if sLazyConnectionEnabled.Valid {
		account.Settings.LazyConnectionEnabled = sLazyConnectionEnabled.Bool
	}
	if sJWTAllowGroups.Valid {
		_ = json.Unmarshal([]byte(sJWTAllowGroups.String), &account.Settings.JWTAllowGroups)
	}
	if sNetworkRange.Valid {
		_ = json.Unmarshal([]byte(sNetworkRange.String), &account.Settings.NetworkRange)
	}

	if sExtraPeerApprovalEnabled.Valid {
		account.Settings.Extra.PeerApprovalEnabled = sExtraPeerApprovalEnabled.Bool
	}
	if sExtraUserApprovalRequired.Valid {
		account.Settings.Extra.UserApprovalRequired = sExtraUserApprovalRequired.Bool
	}
	if sExtraIntegratedValidator.Valid {
		account.Settings.Extra.IntegratedValidator = sExtraIntegratedValidator.String
	}
	if sExtraIntegratedValidatorGroups.Valid {
		_ = json.Unmarshal([]byte(sExtraIntegratedValidatorGroups.String), &account.Settings.Extra.IntegratedValidatorGroups)
	}
	account.InitOnce()
	return &account, nil
}

func (s *SqlStore) getSetupKeys(ctx context.Context, accountID string) ([]types.SetupKey, error) {
	const query = `SELECT id, account_id, key, key_secret, name, type, created_at, expires_at, updated_at, 
	revoked, used_times, last_used, auto_groups, usage_limit, ephemeral, allow_extra_dns_labels FROM setup_keys WHERE account_id = $1`
	rows, err := s.pool.Query(ctx, query, accountID)
	if err != nil {
		return nil, err
	}

	keys, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (types.SetupKey, error) {
		var sk types.SetupKey
		var autoGroups []byte
		var skCreatedAt, expiresAt, updatedAt, lastUsed sql.NullTime
		var revoked, ephemeral, allowExtraDNSLabels sql.NullBool
		var usedTimes, usageLimit sql.NullInt64

		err := row.Scan(&sk.Id, &sk.AccountID, &sk.Key, &sk.KeySecret, &sk.Name, &sk.Type, &skCreatedAt,
			&expiresAt, &updatedAt, &revoked, &usedTimes, &lastUsed, &autoGroups, &usageLimit, &ephemeral, &allowExtraDNSLabels)

		if err == nil {
			if expiresAt.Valid {
				sk.ExpiresAt = &expiresAt.Time
			}
			if skCreatedAt.Valid {
				sk.CreatedAt = skCreatedAt.Time
			}
			if updatedAt.Valid {
				sk.UpdatedAt = updatedAt.Time
				if sk.UpdatedAt.IsZero() {
					sk.UpdatedAt = sk.CreatedAt
				}
			}
			if lastUsed.Valid {
				sk.LastUsed = &lastUsed.Time
			}
			if revoked.Valid {
				sk.Revoked = revoked.Bool
			}
			if usedTimes.Valid {
				sk.UsedTimes = int(usedTimes.Int64)
			}
			if usageLimit.Valid {
				sk.UsageLimit = int(usageLimit.Int64)
			}
			if ephemeral.Valid {
				sk.Ephemeral = ephemeral.Bool
			}
			if allowExtraDNSLabels.Valid {
				sk.AllowExtraDNSLabels = allowExtraDNSLabels.Bool
			}
			if autoGroups != nil {
				_ = json.Unmarshal(autoGroups, &sk.AutoGroups)
			} else {
				sk.AutoGroups = []string{}
			}
		}
		return sk, err
	})
	if err != nil {
		return nil, err
	}
	return keys, nil
}

func (s *SqlStore) getPeers(ctx context.Context, accountID string) ([]nbpeer.Peer, error) {
	const query = `SELECT id, account_id, key, ip, name, dns_label, user_id, ssh_key, ssh_enabled, login_expiration_enabled,
	inactivity_expiration_enabled, last_login, created_at, ephemeral, extra_dns_labels, allow_extra_dns_labels, meta_hostname, 
	meta_go_os, meta_kernel, meta_core, meta_platform, meta_os, meta_os_version, meta_wt_version, meta_ui_version, 
	meta_kernel_version, meta_network_addresses, meta_system_serial_number, meta_system_product_name, meta_system_manufacturer,
	meta_environment, meta_flags, meta_files, peer_status_last_seen, peer_status_connected, peer_status_login_expired, 
	peer_status_requires_approval, location_connection_ip, location_country_code, location_city_name, 
	location_geo_name_id FROM peers WHERE account_id = $1`
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
			peerStatusConnected, peerStatusLoginExpired, peerStatusRequiresApproval                         sql.NullBool
			ip, extraDNS, netAddr, env, flags, files, connIP                                                []byte
			metaHostname, metaGoOS, metaKernel, metaCore, metaPlatform                                      sql.NullString
			metaOS, metaOSVersion, metaWtVersion, metaUIVersion, metaKernelVersion                          sql.NullString
			metaSystemSerialNumber, metaSystemProductName, metaSystemManufacturer                           sql.NullString
			locationCountryCode, locationCityName                                                           sql.NullString
			locationGeoNameID                                                                               sql.NullInt64
		)

		err := row.Scan(&p.ID, &p.AccountID, &p.Key, &ip, &p.Name, &p.DNSLabel, &p.UserID, &p.SSHKey, &sshEnabled,
			&loginExpirationEnabled, &inactivityExpirationEnabled, &lastLogin, &createdAt, &ephemeral, &extraDNS,
			&allowExtraDNSLabels, &metaHostname, &metaGoOS, &metaKernel, &metaCore, &metaPlatform,
			&metaOS, &metaOSVersion, &metaWtVersion, &metaUIVersion, &metaKernelVersion, &netAddr,
			&metaSystemSerialNumber, &metaSystemProductName, &metaSystemManufacturer, &env, &flags, &files,
			&peerStatusLastSeen, &peerStatusConnected, &peerStatusLoginExpired, &peerStatusRequiresApproval, &connIP,
			&locationCountryCode, &locationCityName, &locationGeoNameID)

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
			if ip != nil {
				_ = json.Unmarshal(ip, &p.IP)
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
			if connIP != nil {
				_ = json.Unmarshal(connIP, &p.Location.ConnectionIP)
			}
		}
		return p, err
	})
	if err != nil {
		return nil, err
	}
	return peers, nil
}

func (s *SqlStore) getUsers(ctx context.Context, accountID string) ([]types.User, error) {
	const query = `SELECT id, account_id, role, is_service_user, non_deletable, service_user_name, auto_groups, blocked, pending_approval, last_login, created_at, issued, integration_ref_id, integration_ref_integration_type, email, name FROM users WHERE account_id = $1`
	rows, err := s.pool.Query(ctx, query, accountID)
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

func (s *SqlStore) getGroups(ctx context.Context, accountID string) ([]*types.Group, error) {
	const query = `SELECT id, account_id, name, issued, resources, integration_ref_id, integration_ref_integration_type FROM groups WHERE account_id = $1`
	rows, err := s.pool.Query(ctx, query, accountID)
	if err != nil {
		return nil, err
	}
	groups, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (*types.Group, error) {
		var g types.Group
		var resources []byte
		var refID sql.NullInt64
		var refType sql.NullString
		err := row.Scan(&g.ID, &g.AccountID, &g.Name, &g.Issued, &resources, &refID, &refType)
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

func (s *SqlStore) getPolicies(ctx context.Context, accountID string) ([]*types.Policy, error) {
	const query = `SELECT id, account_id, name, description, enabled, source_posture_checks FROM policies WHERE account_id = $1`
	rows, err := s.pool.Query(ctx, query, accountID)
	if err != nil {
		return nil, err
	}
	policies, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (*types.Policy, error) {
		var p types.Policy
		var checks []byte
		var enabled sql.NullBool
		err := row.Scan(&p.ID, &p.AccountID, &p.Name, &p.Description, &enabled, &checks)
		if err == nil {
			if enabled.Valid {
				p.Enabled = enabled.Bool
			}
			if checks != nil {
				_ = json.Unmarshal(checks, &p.SourcePostureChecks)
			}
		}
		return &p, err
	})
	if err != nil {
		return nil, err
	}
	return policies, nil
}

func (s *SqlStore) getRoutes(ctx context.Context, accountID string) ([]route.Route, error) {
	const query = `SELECT id, account_id, network, domains, keep_route, net_id, description, peer, peer_groups, network_type, masquerade, metric, enabled, groups, access_control_groups, skip_auto_apply FROM routes WHERE account_id = $1`
	rows, err := s.pool.Query(ctx, query, accountID)
	if err != nil {
		return nil, err
	}
	routes, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (route.Route, error) {
		var r route.Route
		var network, domains, peerGroups, groups, accessGroups []byte
		var keepRoute, masquerade, enabled, skipAutoApply sql.NullBool
		var metric sql.NullInt64
		err := row.Scan(&r.ID, &r.AccountID, &network, &domains, &keepRoute, &r.NetID, &r.Description, &r.Peer, &peerGroups, &r.NetworkType, &masquerade, &metric, &enabled, &groups, &accessGroups, &skipAutoApply)
		if err == nil {
			if keepRoute.Valid {
				r.KeepRoute = keepRoute.Bool
			}
			if masquerade.Valid {
				r.Masquerade = masquerade.Bool
			}
			if enabled.Valid {
				r.Enabled = enabled.Bool
			}
			if skipAutoApply.Valid {
				r.SkipAutoApply = skipAutoApply.Bool
			}
			if metric.Valid {
				r.Metric = int(metric.Int64)
			}
			if network != nil {
				_ = json.Unmarshal(network, &r.Network)
			}
			if domains != nil {
				_ = json.Unmarshal(domains, &r.Domains)
			}
			if peerGroups != nil {
				_ = json.Unmarshal(peerGroups, &r.PeerGroups)
			}
			if groups != nil {
				_ = json.Unmarshal(groups, &r.Groups)
			}
			if accessGroups != nil {
				_ = json.Unmarshal(accessGroups, &r.AccessControlGroups)
			}
		}
		return r, err
	})
	if err != nil {
		return nil, err
	}
	return routes, nil
}

func (s *SqlStore) getNameServerGroups(ctx context.Context, accountID string) ([]nbdns.NameServerGroup, error) {
	const query = `SELECT id, account_id, name, description, name_servers, groups, "primary", domains, enabled, search_domains_enabled FROM name_server_groups WHERE account_id = $1`
	rows, err := s.pool.Query(ctx, query, accountID)
	if err != nil {
		return nil, err
	}
	nsgs, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (nbdns.NameServerGroup, error) {
		var n nbdns.NameServerGroup
		var ns, groups, domains []byte
		var primary, enabled, searchDomainsEnabled sql.NullBool
		err := row.Scan(&n.ID, &n.AccountID, &n.Name, &n.Description, &ns, &groups, &primary, &domains, &enabled, &searchDomainsEnabled)
		if err == nil {
			if primary.Valid {
				n.Primary = primary.Bool
			}
			if enabled.Valid {
				n.Enabled = enabled.Bool
			}
			if searchDomainsEnabled.Valid {
				n.SearchDomainsEnabled = searchDomainsEnabled.Bool
			}
			if ns != nil {
				_ = json.Unmarshal(ns, &n.NameServers)
			} else {
				n.NameServers = []nbdns.NameServer{}
			}
			if groups != nil {
				_ = json.Unmarshal(groups, &n.Groups)
			} else {
				n.Groups = []string{}
			}
			if domains != nil {
				_ = json.Unmarshal(domains, &n.Domains)
			} else {
				n.Domains = []string{}
			}
		}
		return n, err
	})
	if err != nil {
		return nil, err
	}
	return nsgs, nil
}

func (s *SqlStore) getPostureChecks(ctx context.Context, accountID string) ([]*posture.Checks, error) {
	const query = `SELECT id, account_id, name, description, checks FROM posture_checks WHERE account_id = $1`
	rows, err := s.pool.Query(ctx, query, accountID)
	if err != nil {
		return nil, err
	}
	checks, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (*posture.Checks, error) {
		var c posture.Checks
		var checksDef []byte
		err := row.Scan(&c.ID, &c.AccountID, &c.Name, &c.Description, &checksDef)
		if err == nil && checksDef != nil {
			_ = json.Unmarshal(checksDef, &c.Checks)
		}
		return &c, err
	})
	if err != nil {
		return nil, err
	}
	return checks, nil
}

func (s *SqlStore) getNetworks(ctx context.Context, accountID string) ([]*networkTypes.Network, error) {
	const query = `SELECT id, account_id, name, description FROM networks WHERE account_id = $1`
	rows, err := s.pool.Query(ctx, query, accountID)
	if err != nil {
		return nil, err
	}
	networks, err := pgx.CollectRows(rows, pgx.RowToStructByName[networkTypes.Network])
	if err != nil {
		return nil, err
	}
	result := make([]*networkTypes.Network, len(networks))
	for i := range networks {
		result[i] = &networks[i]
	}
	return result, nil
}

func (s *SqlStore) getNetworkRouters(ctx context.Context, accountID string) ([]*routerTypes.NetworkRouter, error) {
	const query = `SELECT id, network_id, account_id, peer, peer_groups, masquerade, metric, enabled FROM network_routers WHERE account_id = $1`
	rows, err := s.pool.Query(ctx, query, accountID)
	if err != nil {
		return nil, err
	}
	routers, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (routerTypes.NetworkRouter, error) {
		var r routerTypes.NetworkRouter
		var peerGroups []byte
		var masquerade, enabled sql.NullBool
		var metric sql.NullInt64
		err := row.Scan(&r.ID, &r.NetworkID, &r.AccountID, &r.Peer, &peerGroups, &masquerade, &metric, &enabled)
		if err == nil {
			if masquerade.Valid {
				r.Masquerade = masquerade.Bool
			}
			if enabled.Valid {
				r.Enabled = enabled.Bool
			}
			if metric.Valid {
				r.Metric = int(metric.Int64)
			}
			if peerGroups != nil {
				_ = json.Unmarshal(peerGroups, &r.PeerGroups)
			}
		}
		return r, err
	})
	if err != nil {
		return nil, err
	}
	result := make([]*routerTypes.NetworkRouter, len(routers))
	for i := range routers {
		result[i] = &routers[i]
	}
	return result, nil
}

func (s *SqlStore) getNetworkResources(ctx context.Context, accountID string) ([]*resourceTypes.NetworkResource, error) {
	const query = `SELECT id, network_id, account_id, name, description, type, domain, prefix, enabled FROM network_resources WHERE account_id = $1`
	rows, err := s.pool.Query(ctx, query, accountID)
	if err != nil {
		return nil, err
	}
	resources, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (resourceTypes.NetworkResource, error) {
		var r resourceTypes.NetworkResource
		var prefix []byte
		var enabled sql.NullBool
		err := row.Scan(&r.ID, &r.NetworkID, &r.AccountID, &r.Name, &r.Description, &r.Type, &r.Domain, &prefix, &enabled)
		if err == nil {
			if enabled.Valid {
				r.Enabled = enabled.Bool
			}
			if prefix != nil {
				_ = json.Unmarshal(prefix, &r.Prefix)
			}
		}
		return r, err
	})
	if err != nil {
		return nil, err
	}
	result := make([]*resourceTypes.NetworkResource, len(resources))
	for i := range resources {
		result[i] = &resources[i]
	}
	return result, nil
}

func (s *SqlStore) getAccountOnboarding(ctx context.Context, accountID string, account *types.Account) error {
	const query = `SELECT account_id, onboarding_flow_pending, signup_form_pending, created_at, updated_at FROM account_onboardings WHERE account_id = $1`
	var onboardingFlowPending, signupFormPending sql.NullBool
	var createdAt, updatedAt sql.NullTime
	err := s.pool.QueryRow(ctx, query, accountID).Scan(
		&account.Onboarding.AccountID,
		&onboardingFlowPending,
		&signupFormPending,
		&createdAt,
		&updatedAt,
	)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if createdAt.Valid {
		account.Onboarding.CreatedAt = createdAt.Time
	}
	if updatedAt.Valid {
		account.Onboarding.UpdatedAt = updatedAt.Time
	}
	if onboardingFlowPending.Valid {
		account.Onboarding.OnboardingFlowPending = onboardingFlowPending.Bool
	}
	if signupFormPending.Valid {
		account.Onboarding.SignupFormPending = signupFormPending.Bool
	}
	return nil
}

func (s *SqlStore) getPersonalAccessTokens(ctx context.Context, userIDs []string) ([]types.PersonalAccessToken, error) {
	if len(userIDs) == 0 {
		return nil, nil
	}
	const query = `SELECT id, user_id, name, hashed_token, expiration_date, created_by, created_at, last_used FROM personal_access_tokens WHERE user_id = ANY($1)`
	rows, err := s.pool.Query(ctx, query, userIDs)
	if err != nil {
		return nil, err
	}
	pats, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (types.PersonalAccessToken, error) {
		var pat types.PersonalAccessToken
		var expirationDate, lastUsed, createdAt sql.NullTime
		err := row.Scan(&pat.ID, &pat.UserID, &pat.Name, &pat.HashedToken, &expirationDate, &pat.CreatedBy, &createdAt, &lastUsed)
		if err == nil {
			if expirationDate.Valid {
				pat.ExpirationDate = &expirationDate.Time
			}
			if createdAt.Valid {
				pat.CreatedAt = createdAt.Time
			}
			if lastUsed.Valid {
				pat.LastUsed = &lastUsed.Time
			}
		}
		return pat, err
	})
	if err != nil {
		return nil, err
	}
	return pats, nil
}

func (s *SqlStore) getPolicyRules(ctx context.Context, policyIDs []string) ([]*types.PolicyRule, error) {
	if len(policyIDs) == 0 {
		return nil, nil
	}
	const query = `SELECT id, policy_id, name, description, enabled, action, destinations, destination_resource, sources, source_resource, bidirectional, protocol, ports, port_ranges, authorized_groups, authorized_user FROM policy_rules WHERE policy_id = ANY($1)`
	rows, err := s.pool.Query(ctx, query, policyIDs)
	if err != nil {
		return nil, err
	}
	rules, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (*types.PolicyRule, error) {
		var r types.PolicyRule
		var dest, destRes, sources, sourceRes, ports, portRanges, authorizedGroups []byte
		var enabled, bidirectional sql.NullBool
		var authorizedUser sql.NullString
		err := row.Scan(&r.ID, &r.PolicyID, &r.Name, &r.Description, &enabled, &r.Action, &dest, &destRes, &sources, &sourceRes, &bidirectional, &r.Protocol, &ports, &portRanges, &authorizedGroups, &authorizedUser)
		if err == nil {
			if enabled.Valid {
				r.Enabled = enabled.Bool
			}
			if bidirectional.Valid {
				r.Bidirectional = bidirectional.Bool
			}
			if dest != nil {
				_ = json.Unmarshal(dest, &r.Destinations)
			}
			if destRes != nil {
				_ = json.Unmarshal(destRes, &r.DestinationResource)
			}
			if sources != nil {
				_ = json.Unmarshal(sources, &r.Sources)
			}
			if sourceRes != nil {
				_ = json.Unmarshal(sourceRes, &r.SourceResource)
			}
			if ports != nil {
				_ = json.Unmarshal(ports, &r.Ports)
			}
			if portRanges != nil {
				_ = json.Unmarshal(portRanges, &r.PortRanges)
			}
			if authorizedGroups != nil {
				_ = json.Unmarshal(authorizedGroups, &r.AuthorizedGroups)
			}
			if authorizedUser.Valid {
				r.AuthorizedUser = authorizedUser.String
			}
		}
		return &r, err
	})
	if err != nil {
		return nil, err
	}
	return rules, nil
}

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

func (s *SqlStore) GetAnyAccountID(ctx context.Context) (string, error) {
	var account types.Account
	result := s.db.Select("id").Order("created_at desc").Limit(1).Find(&account)
	if result.Error != nil {
		return "", status.NewGetAccountFromStoreError(result.Error)
	}
	if result.RowsAffected == 0 {
		return "", status.Errorf(status.NotFound, "account not found: index lookup failed")
	}

	return account.Id, nil
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

func (s *SqlStore) GetAccountIDBySetupKey(ctx context.Context, setupKey string) (string, error) {
	var accountID string
	result := s.db.Model(&types.SetupKey{}).Select("account_id").Where(GetKeyQueryCondition(s), setupKey).Take(&accountID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return "", status.NewSetupKeyNotFoundError(setupKey)
		}
		log.WithContext(ctx).Errorf("failed to get account ID by setup key from store: %v", result.Error)
		return "", status.Errorf(status.Internal, "failed to get account ID by setup key from store")
	}

	if accountID == "" {
		return "", status.Errorf(status.NotFound, "account not found: index lookup failed")
	}

	return accountID, nil
}

func (s *SqlStore) GetTakenIPs(ctx context.Context, lockStrength LockingStrength, accountID string) ([]net.IP, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var ipJSONStrings []string

	// Fetch the IP addresses as JSON strings
	result := tx.Model(&nbpeer.Peer{}).
		Where("account_id = ?", accountID).
		Pluck("ip", &ipJSONStrings)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(status.NotFound, "no peers found for the account")
		}
		return nil, status.Errorf(status.Internal, "issue getting IPs from store: %s", result.Error)
	}

	// Convert the JSON strings to net.IP objects
	ips := make([]net.IP, len(ipJSONStrings))
	for i, ipJSON := range ipJSONStrings {
		var ip net.IP
		if err := json.Unmarshal([]byte(ipJSON), &ip); err != nil {
			return nil, status.Errorf(status.Internal, "issue parsing IP JSON from store")
		}
		ips[i] = ip
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

func (s *SqlStore) GetAccountNetwork(ctx context.Context, lockStrength LockingStrength, accountID string) (*types.Network, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var accountNetwork types.AccountNetwork
	if err := tx.Model(&types.Account{}).Where(idQueryCondition, accountID).Take(&accountNetwork).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.NewAccountNotFoundError(accountID)
		}
		return nil, status.Errorf(status.Internal, "issue getting network from store: %s", err)
	}
	return accountNetwork.Network, nil
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

func (s *SqlStore) GetAccountSettings(ctx context.Context, lockStrength LockingStrength, accountID string) (*types.Settings, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var accountSettings types.AccountSettings
	if err := tx.Model(&types.Account{}).Where(idQueryCondition, accountID).Take(&accountSettings).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(status.NotFound, "settings not found")
		}
		return nil, status.Errorf(status.Internal, "issue getting settings from store: %s", err)
	}
	return accountSettings.Settings, nil
}

func (s *SqlStore) GetAccountCreatedBy(ctx context.Context, lockStrength LockingStrength, accountID string) (string, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var createdBy string
	result := tx.Model(&types.Account{}).
		Select("created_by").Take(&createdBy, idQueryCondition, accountID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return "", status.NewAccountNotFoundError(accountID)
		}
		return "", status.NewGetAccountFromStoreError(result.Error)
	}

	return createdBy, nil
}

// SaveUserLastLogin stores the last login time for a user in DB.
func (s *SqlStore) SaveUserLastLogin(ctx context.Context, accountID, userID string, lastLogin time.Time) error {
	var user types.User
	result := s.db.Take(&user, accountAndIDQueryCondition, accountID, userID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return status.NewUserNotFoundError(userID)
		}
		return status.NewGetUserFromStoreError()
	}

	if !lastLogin.IsZero() {
		user.LastLogin = &lastLogin
		return s.db.Save(&user).Error
	}

	return nil
}

func (s *SqlStore) GetPostureCheckByChecksDefinition(accountID string, checks *posture.ChecksDefinition) (*posture.Checks, error) {
	definitionJSON, err := json.Marshal(checks)
	if err != nil {
		return nil, err
	}

	var postureCheck posture.Checks
	err = s.db.Where("account_id = ? AND checks = ?", accountID, string(definitionJSON)).Take(&postureCheck).Error
	if err != nil {
		return nil, err
	}

	return &postureCheck, nil
}

// Close closes the underlying DB connection
func (s *SqlStore) Close(_ context.Context) error {
	sql, err := s.db.DB()
	if err != nil {
		return fmt.Errorf("get db: %w", err)
	}
	return sql.Close()
}

// GetStoreEngine returns underlying store engine
func (s *SqlStore) GetStoreEngine() types.Engine {
	return s.storeEngine
}

// NewSqliteStore creates a new SQLite store.
func NewSqliteStore(ctx context.Context, dataDir string, metrics telemetry.AppMetrics, skipMigration bool) (*SqlStore, error) {
	storeStr := fmt.Sprintf("%s?cache=shared", storeSqliteFileName)
	if runtime.GOOS == "windows" {
		// Vo avoid `The process cannot access the file because it is being used by another process` on Windows
		storeStr = storeSqliteFileName
	}

	file := filepath.Join(dataDir, storeStr)
	db, err := gorm.Open(sqlite.Open(file), getGormConfig())
	if err != nil {
		return nil, err
	}

	return NewSqlStore(ctx, db, types.SqliteStoreEngine, metrics, skipMigration)
}

// NewPostgresqlStore creates a new Postgres store.
func NewPostgresqlStore(ctx context.Context, dsn string, metrics telemetry.AppMetrics, skipMigration bool) (*SqlStore, error) {
	db, err := gorm.Open(postgres.Open(dsn), getGormConfig())
	if err != nil {
		return nil, err
	}
	pool, err := connectToPgDb(context.Background(), dsn)
	if err != nil {
		return nil, err
	}
	store, err := NewSqlStore(ctx, db, types.PostgresStoreEngine, metrics, skipMigration)
	if err != nil {
		pool.Close()
		return nil, err
	}
	store.pool = pool
	return store, nil
}

func connectToPgDb(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("unable to parse database config: %w", err)
	}

	config.MaxConns = pgMaxConnections
	config.MinConns = pgMinConnections
	config.MaxConnLifetime = pgMaxConnLifetime
	config.HealthCheckPeriod = pgHealthCheckPeriod

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("unable to create connection pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("unable to ping database: %w", err)
	}

	return pool, nil
}

// NewMysqlStore creates a new MySQL store.
func NewMysqlStore(ctx context.Context, dsn string, metrics telemetry.AppMetrics, skipMigration bool) (*SqlStore, error) {
	db, err := gorm.Open(mysql.Open(dsn+"?charset=utf8&parseTime=True&loc=Local"), getGormConfig())
	if err != nil {
		return nil, err
	}

	return NewSqlStore(ctx, db, types.MysqlStoreEngine, metrics, skipMigration)
}

func getGormConfig() *gorm.Config {
	return &gorm.Config{
		Logger:          logger.Default.LogMode(logger.Silent),
		CreateBatchSize: 400,
	}
}

// newPostgresStore initializes a new Postgres store.
func newPostgresStore(ctx context.Context, metrics telemetry.AppMetrics, skipMigration bool) (Store, error) {
	dsn, ok := os.LookupEnv(postgresDsnEnv)
	if !ok {
		return nil, fmt.Errorf("%s is not set", postgresDsnEnv)
	}
	return NewPostgresqlStore(ctx, dsn, metrics, skipMigration)
}

// newMysqlStore initializes a new MySQL store.
func newMysqlStore(ctx context.Context, metrics telemetry.AppMetrics, skipMigration bool) (Store, error) {
	dsn, ok := os.LookupEnv(mysqlDsnEnv)
	if !ok {
		return nil, fmt.Errorf("%s is not set", mysqlDsnEnv)
	}
	return NewMysqlStore(ctx, dsn, metrics, skipMigration)
}

// NewSqliteStoreFromFileStore restores a store from FileStore and stores SQLite DB in the file located in datadir.
func NewSqliteStoreFromFileStore(ctx context.Context, fileStore *FileStore, dataDir string, metrics telemetry.AppMetrics, skipMigration bool) (*SqlStore, error) {
	store, err := NewSqliteStore(ctx, dataDir, metrics, skipMigration)
	if err != nil {
		return nil, err
	}

	err = store.SaveInstallationID(ctx, fileStore.InstallationID)
	if err != nil {
		return nil, err
	}

	for _, account := range fileStore.GetAllAccounts(ctx) {
		_, err = account.GetGroupAll()
		if err != nil {
			if err := account.AddAllGroup(false); err != nil {
				return nil, err
			}
		}

		err := store.SaveAccount(ctx, account)
		if err != nil {
			return nil, err
		}
	}

	return store, nil
}

// NewPostgresqlStoreFromSqlStore restores a store from SqlStore and stores Postgres DB.
func NewPostgresqlStoreFromSqlStore(ctx context.Context, sqliteStore *SqlStore, dsn string, metrics telemetry.AppMetrics) (*SqlStore, error) {
	store, err := NewPostgresqlStoreForTests(ctx, dsn, metrics, false)
	if err != nil {
		return nil, err
	}

	err = store.SaveInstallationID(ctx, sqliteStore.GetInstallationID())
	if err != nil {
		return nil, err
	}

	for _, account := range sqliteStore.GetAllAccounts(ctx) {
		err := store.SaveAccount(ctx, account)
		if err != nil {
			return nil, err
		}
	}

	return store, nil
}

// used for tests only
func NewPostgresqlStoreForTests(ctx context.Context, dsn string, metrics telemetry.AppMetrics, skipMigration bool) (*SqlStore, error) {
	db, err := gorm.Open(postgres.Open(dsn), getGormConfig())
	if err != nil {
		return nil, err
	}
	pool, err := connectToPgDbForTests(context.Background(), dsn)
	if err != nil {
		return nil, err
	}
	store, err := NewSqlStore(ctx, db, types.PostgresStoreEngine, metrics, skipMigration)
	if err != nil {
		pool.Close()
		return nil, err
	}
	store.pool = pool
	return store, nil
}

// used for tests only
func connectToPgDbForTests(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("unable to parse database config: %w", err)
	}

	config.MaxConns = 5
	config.MinConns = 1
	config.MaxConnLifetime = 30 * time.Second
	config.HealthCheckPeriod = 10 * time.Second

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("unable to create connection pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("unable to ping database: %w", err)
	}

	return pool, nil
}

// NewMysqlStoreFromSqlStore restores a store from SqlStore and stores MySQL DB.
func NewMysqlStoreFromSqlStore(ctx context.Context, sqliteStore *SqlStore, dsn string, metrics telemetry.AppMetrics) (*SqlStore, error) {
	store, err := NewMysqlStore(ctx, dsn, metrics, false)
	if err != nil {
		return nil, err
	}

	err = store.SaveInstallationID(ctx, sqliteStore.GetInstallationID())
	if err != nil {
		return nil, err
	}

	for _, account := range sqliteStore.GetAllAccounts(ctx) {
		err := store.SaveAccount(ctx, account)
		if err != nil {
			return nil, err
		}
	}

	return store, nil
}

func (s *SqlStore) GetSetupKeyBySecret(ctx context.Context, lockStrength LockingStrength, key string) (*types.SetupKey, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var setupKey types.SetupKey
	result := tx.
		Take(&setupKey, GetKeyQueryCondition(s), key)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.Errorf(status.PreconditionFailed, "setup key not found")
		}
		log.WithContext(ctx).Errorf("failed to get setup key by secret from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get setup key by secret from store")
	}
	return &setupKey, nil
}

func (s *SqlStore) IncrementSetupKeyUsage(ctx context.Context, setupKeyID string) error {
	result := s.db.Model(&types.SetupKey{}).
		Where(idQueryCondition, setupKeyID).
		Updates(map[string]interface{}{
			"used_times": gorm.Expr("used_times + 1"),
			"last_used":  time.Now(),
		})

	if result.Error != nil {
		return status.Errorf(status.Internal, "issue incrementing setup key usage count: %s", result.Error)
	}

	if result.RowsAffected == 0 {
		return status.NewSetupKeyNotFoundError(setupKeyID)
	}

	return nil
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

// GetPeerGroups retrieves all groups assigned to a specific peer in a given account.
func (s *SqlStore) GetPeerGroups(ctx context.Context, lockStrength LockingStrength, accountId string, peerId string) ([]*types.Group, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var groups []*types.Group
	query := tx.
		Joins("JOIN group_peers ON group_peers.group_id = groups.id").
		Where("group_peers.peer_id = ?", peerId).
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
		query = query.Where("ip LIKE ?", "%"+ipFilter+"%")
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
		Where("login_expiration_enabled = ? AND user_id IS NOT NULL AND user_id != ''", true).
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

func (s *SqlStore) IncrementNetworkSerial(ctx context.Context, accountId string) error {
	result := s.db.Model(&types.Account{}).Where(idQueryCondition, accountId).Update("network_serial", gorm.Expr("network_serial + 1"))
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to increment network serial count in store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to increment network serial count in store")
	}
	return nil
}

func (s *SqlStore) ExecuteInTransaction(ctx context.Context, operation func(store Store) error) error {
	timeoutCtx, cancel := context.WithTimeout(context.Background(), s.transactionTimeout)
	defer cancel()

	startTime := time.Now()
	tx := s.db.WithContext(timeoutCtx).Begin()
	if tx.Error != nil {
		return tx.Error
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
			panic(r)
		}
	}()

	if s.storeEngine == types.PostgresStoreEngine {
		if err := tx.Exec("SET LOCAL statement_timeout = '1min'").Error; err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to set statement timeout: %w", err)
		}
		if err := tx.Exec("SET LOCAL lock_timeout = '1min'").Error; err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to set lock timeout: %w", err)
		}
	}

	// For MySQL, disable FK checks within this transaction to avoid deadlocks
	// This is session-scoped and doesn't require SUPER privileges
	if s.storeEngine == types.MysqlStoreEngine {
		if err := tx.Exec("SET FOREIGN_KEY_CHECKS = 0").Error; err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to disable FK checks: %w", err)
		}
	}

	repo := s.withTx(tx)
	err := operation(repo)
	if err != nil {
		tx.Rollback()
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(timeoutCtx.Err(), context.DeadlineExceeded) {
			log.WithContext(ctx).Warnf("transaction exceeded %s timeout after %v, stack: %s", s.transactionTimeout, time.Since(startTime), debug.Stack())
		}
		return err
	}

	// Re-enable FK checks before commit (optional, as transaction end resets it)
	if s.storeEngine == types.MysqlStoreEngine {
		if err := tx.Exec("SET FOREIGN_KEY_CHECKS = 1").Error; err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to re-enable FK checks: %w", err)
		}
	}

	err = tx.Commit().Error
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(timeoutCtx.Err(), context.DeadlineExceeded) {
			log.WithContext(ctx).Warnf("transaction commit exceeded %s timeout after %v, stack: %s", s.transactionTimeout, time.Since(startTime), debug.Stack())
		}
		return err
	}

	log.WithContext(ctx).Tracef("transaction took %v", time.Since(startTime))
	if s.metrics != nil {
		s.metrics.StoreMetrics().CountTransactionDuration(time.Since(startTime))
	}

	return nil
}

func (s *SqlStore) withTx(tx *gorm.DB) Store {
	return &SqlStore{
		db:           tx,
		storeEngine:  s.storeEngine,
		fieldEncrypt: s.fieldEncrypt,
	}
}

// transaction wraps a GORM transaction with MySQL-specific FK checks handling
// Use this instead of db.Transaction() directly to avoid deadlocks on MySQL/Aurora
func (s *SqlStore) transaction(fn func(*gorm.DB) error) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		// For MySQL, disable FK checks within this transaction to avoid deadlocks
		// This is session-scoped and doesn't require SUPER privileges
		if s.storeEngine == types.MysqlStoreEngine {
			if err := tx.Exec("SET FOREIGN_KEY_CHECKS = 0").Error; err != nil {
				return fmt.Errorf("failed to disable FK checks: %w", err)
			}
		}

		err := fn(tx)

		// Re-enable FK checks before commit (optional, as transaction end resets it)
		if s.storeEngine == types.MysqlStoreEngine && err == nil {
			if fkErr := tx.Exec("SET FOREIGN_KEY_CHECKS = 1").Error; fkErr != nil {
				return fmt.Errorf("failed to re-enable FK checks: %w", fkErr)
			}
		}

		return err
	})
}

func (s *SqlStore) GetDB() *gorm.DB {
	return s.db
}

// SetFieldEncrypt sets the field encryptor for encrypting sensitive user data.
func (s *SqlStore) SetFieldEncrypt(enc *crypt.FieldEncrypt) {
	s.fieldEncrypt = enc
}

func (s *SqlStore) GetAccountDNSSettings(ctx context.Context, lockStrength LockingStrength, accountID string) (*types.DNSSettings, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var accountDNSSettings types.AccountDNSSettings
	result := tx.Model(&types.Account{}).
		Take(&accountDNSSettings, idQueryCondition, accountID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.NewAccountNotFoundError(accountID)
		}
		log.WithContext(ctx).Errorf("failed to get dns settings from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get dns settings from store")
	}
	return &accountDNSSettings.DNSSettings, nil
}

// AccountExists checks whether an account exists by the given ID.
func (s *SqlStore) AccountExists(ctx context.Context, lockStrength LockingStrength, id string) (bool, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var accountID string
	result := tx.Model(&types.Account{}).
		Select("id").Take(&accountID, idQueryCondition, id)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, result.Error
	}

	return accountID != "", nil
}

// GetAccountDomainAndCategory retrieves the Domain and DomainCategory fields for an account based on the given accountID.
func (s *SqlStore) GetAccountDomainAndCategory(ctx context.Context, lockStrength LockingStrength, accountID string) (string, string, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var account types.Account
	result := tx.Model(&types.Account{}).Select("domain", "domain_category").
		Where(idQueryCondition, accountID).Take(&account)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return "", "", status.Errorf(status.NotFound, "account not found")
		}
		return "", "", status.Errorf(status.Internal, "failed to get domain category from store: %v", result.Error)
	}

	return account.Domain, account.DomainCategory, nil
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

	if err := s.db.Omit(clause.Associations).Save(group).Error; err != nil {
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

// GetAccountPolicies retrieves policies for an account.
func (s *SqlStore) GetAccountPolicies(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*types.Policy, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var policies []*types.Policy
	result := tx.
		Preload(clause.Associations).Find(&policies, accountIDCondition, accountID)
	if err := result.Error; err != nil {
		log.WithContext(ctx).Errorf("failed to get policies from the store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get policies from store")
	}

	return policies, nil
}

// GetPolicyByID retrieves a policy by its ID and account ID.
func (s *SqlStore) GetPolicyByID(ctx context.Context, lockStrength LockingStrength, accountID, policyID string) (*types.Policy, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var policy *types.Policy

	result := tx.Preload(clause.Associations).
		Take(&policy, accountAndIDQueryCondition, accountID, policyID)
	if err := result.Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.NewPolicyNotFoundError(policyID)
		}
		log.WithContext(ctx).Errorf("failed to get policy from store: %s", err)
		return nil, status.Errorf(status.Internal, "failed to get policy from store")
	}

	return policy, nil
}

func (s *SqlStore) CreatePolicy(ctx context.Context, policy *types.Policy) error {
	result := s.db.Create(policy)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to create policy in store: %s", result.Error)
		return status.Errorf(status.Internal, "failed to create policy in store")
	}

	return nil
}

// SavePolicy saves a policy to the database.
func (s *SqlStore) SavePolicy(ctx context.Context, policy *types.Policy) error {
	result := s.db.Session(&gorm.Session{FullSaveAssociations: true}).Save(policy)
	if err := result.Error; err != nil {
		log.WithContext(ctx).Errorf("failed to save policy to the store: %s", err)
		return status.Errorf(status.Internal, "failed to save policy to store")
	}
	return nil
}

func (s *SqlStore) DeletePolicy(ctx context.Context, accountID, policyID string) error {
	return s.transaction(func(tx *gorm.DB) error {
		if err := tx.Where("policy_id = ?", policyID).Delete(&types.PolicyRule{}).Error; err != nil {
			return fmt.Errorf("delete policy rules: %w", err)
		}

		result := tx.
			Where(accountAndIDQueryCondition, accountID, policyID).
			Delete(&types.Policy{})

		if err := result.Error; err != nil {
			log.WithContext(ctx).Errorf("failed to delete policy from store: %s", err)
			return status.Errorf(status.Internal, "failed to delete policy from store")
		}

		if result.RowsAffected == 0 {
			return status.NewPolicyNotFoundError(policyID)
		}

		return nil
	})
}

func (s *SqlStore) GetPolicyRulesByResourceID(ctx context.Context, lockStrength LockingStrength, accountID string, resourceID string) ([]*types.PolicyRule, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var policyRules []*types.PolicyRule
	resourceIDPattern := `%"ID":"` + resourceID + `"%`
	result := tx.Where("source_resource LIKE ? OR destination_resource LIKE ?", resourceIDPattern, resourceIDPattern).
		Find(&policyRules)

	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get policy rules for resource id from store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get policy rules for resource id from store")
	}

	return policyRules, nil
}

// GetAccountPostureChecks retrieves posture checks for an account.
func (s *SqlStore) GetAccountPostureChecks(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*posture.Checks, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var postureChecks []*posture.Checks
	result := tx.Find(&postureChecks, accountIDCondition, accountID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get posture checks from store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get posture checks from store")
	}

	return postureChecks, nil
}

// GetPostureChecksByID retrieves posture checks by their ID and account ID.
func (s *SqlStore) GetPostureChecksByID(ctx context.Context, lockStrength LockingStrength, accountID, postureChecksID string) (*posture.Checks, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var postureCheck *posture.Checks
	result := tx.
		Take(&postureCheck, accountAndIDQueryCondition, accountID, postureChecksID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.NewPostureChecksNotFoundError(postureChecksID)
		}
		log.WithContext(ctx).Errorf("failed to get posture check from store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get posture check from store")
	}

	return postureCheck, nil
}

// GetPostureChecksByIDs retrieves posture checks by their IDs and account ID.
func (s *SqlStore) GetPostureChecksByIDs(ctx context.Context, lockStrength LockingStrength, accountID string, postureChecksIDs []string) (map[string]*posture.Checks, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var postureChecks []*posture.Checks
	result := tx.Find(&postureChecks, accountAndIDsQueryCondition, accountID, postureChecksIDs)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get posture checks by ID's from store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get posture checks by ID's from store")
	}

	postureChecksMap := make(map[string]*posture.Checks)
	for _, postureCheck := range postureChecks {
		postureChecksMap[postureCheck.ID] = postureCheck
	}

	return postureChecksMap, nil
}

// SavePostureChecks saves a posture checks to the database.
func (s *SqlStore) SavePostureChecks(ctx context.Context, postureCheck *posture.Checks) error {
	result := s.db.Save(postureCheck)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to save posture checks to store: %s", result.Error)
		return status.Errorf(status.Internal, "failed to save posture checks to store")
	}

	return nil
}

// DeletePostureChecks deletes a posture checks from the database.
func (s *SqlStore) DeletePostureChecks(ctx context.Context, accountID, postureChecksID string) error {
	result := s.db.Delete(&posture.Checks{}, accountAndIDQueryCondition, accountID, postureChecksID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to delete posture checks from store: %s", result.Error)
		return status.Errorf(status.Internal, "failed to delete posture checks from store")
	}

	if result.RowsAffected == 0 {
		return status.NewPostureChecksNotFoundError(postureChecksID)
	}

	return nil
}

// GetAccountRoutes retrieves network routes for an account.
func (s *SqlStore) GetAccountRoutes(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*route.Route, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var routes []*route.Route
	result := tx.Find(&routes, accountIDCondition, accountID)
	if err := result.Error; err != nil {
		log.WithContext(ctx).Errorf("failed to get routes from the store: %s", err)
		return nil, status.Errorf(status.Internal, "failed to get routes from store")
	}

	return routes, nil
}

// GetRouteByID retrieves a route by its ID and account ID.
func (s *SqlStore) GetRouteByID(ctx context.Context, lockStrength LockingStrength, accountID string, routeID string) (*route.Route, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var route *route.Route
	result := tx.Take(&route, accountAndIDQueryCondition, accountID, routeID)
	if err := result.Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.NewRouteNotFoundError(routeID)
		}
		log.WithContext(ctx).Errorf("failed to get route from the store: %s", err)
		return nil, status.Errorf(status.Internal, "failed to get route from store")
	}

	return route, nil
}

// SaveRoute saves a route to the database.
func (s *SqlStore) SaveRoute(ctx context.Context, route *route.Route) error {
	result := s.db.Save(route)
	if err := result.Error; err != nil {
		log.WithContext(ctx).Errorf("failed to save route to the store: %s", err)
		return status.Errorf(status.Internal, "failed to save route to store")
	}

	return nil
}

// DeleteRoute deletes a route from the database.
func (s *SqlStore) DeleteRoute(ctx context.Context, accountID, routeID string) error {
	result := s.db.Delete(&route.Route{}, accountAndIDQueryCondition, accountID, routeID)
	if err := result.Error; err != nil {
		log.WithContext(ctx).Errorf("failed to delete route from the store: %s", err)
		return status.Errorf(status.Internal, "failed to delete route from store")
	}

	if result.RowsAffected == 0 {
		return status.NewRouteNotFoundError(routeID)
	}

	return nil
}

// GetAccountSetupKeys retrieves setup keys for an account.
func (s *SqlStore) GetAccountSetupKeys(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*types.SetupKey, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var setupKeys []*types.SetupKey
	result := tx.
		Find(&setupKeys, accountIDCondition, accountID)
	if err := result.Error; err != nil {
		log.WithContext(ctx).Errorf("failed to get setup keys from the store: %s", err)
		return nil, status.Errorf(status.Internal, "failed to get setup keys from store")
	}

	return setupKeys, nil
}

// GetSetupKeyByID retrieves a setup key by its ID and account ID.
func (s *SqlStore) GetSetupKeyByID(ctx context.Context, lockStrength LockingStrength, accountID, setupKeyID string) (*types.SetupKey, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var setupKey *types.SetupKey
	result := tx.Take(&setupKey, accountAndIDQueryCondition, accountID, setupKeyID)
	if err := result.Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.NewSetupKeyNotFoundError(setupKeyID)
		}
		log.WithContext(ctx).Errorf("failed to get setup key from the store: %s", err)
		return nil, status.Errorf(status.Internal, "failed to get setup key from store")
	}

	return setupKey, nil
}

// SaveSetupKey saves a setup key to the database.
func (s *SqlStore) SaveSetupKey(ctx context.Context, setupKey *types.SetupKey) error {
	result := s.db.Save(setupKey)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to save setup key to store: %s", result.Error)
		return status.Errorf(status.Internal, "failed to save setup key to store")
	}

	return nil
}

// DeleteSetupKey deletes a setup key from the database.
func (s *SqlStore) DeleteSetupKey(ctx context.Context, accountID, keyID string) error {
	result := s.db.Delete(&types.SetupKey{}, accountAndIDQueryCondition, accountID, keyID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to delete setup key from store: %s", result.Error)
		return status.Errorf(status.Internal, "failed to delete setup key from store")
	}

	if result.RowsAffected == 0 {
		return status.NewSetupKeyNotFoundError(keyID)
	}

	return nil
}

// GetAccountNameServerGroups retrieves name server groups for an account.
func (s *SqlStore) GetAccountNameServerGroups(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*nbdns.NameServerGroup, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var nsGroups []*nbdns.NameServerGroup
	result := tx.Find(&nsGroups, accountIDCondition, accountID)
	if err := result.Error; err != nil {
		log.WithContext(ctx).Errorf("failed to get name server groups from the store: %s", err)
		return nil, status.Errorf(status.Internal, "failed to get name server groups from store")
	}

	return nsGroups, nil
}

// GetNameServerGroupByID retrieves a name server group by its ID and account ID.
func (s *SqlStore) GetNameServerGroupByID(ctx context.Context, lockStrength LockingStrength, accountID, nsGroupID string) (*nbdns.NameServerGroup, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var nsGroup *nbdns.NameServerGroup
	result := tx.
		Take(&nsGroup, accountAndIDQueryCondition, accountID, nsGroupID)
	if err := result.Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.NewNameServerGroupNotFoundError(nsGroupID)
		}
		log.WithContext(ctx).Errorf("failed to get name server group from the store: %s", err)
		return nil, status.Errorf(status.Internal, "failed to get name server group from store")
	}

	return nsGroup, nil
}

// SaveNameServerGroup saves a name server group to the database.
func (s *SqlStore) SaveNameServerGroup(ctx context.Context, nameServerGroup *nbdns.NameServerGroup) error {
	result := s.db.Save(nameServerGroup)
	if err := result.Error; err != nil {
		log.WithContext(ctx).Errorf("failed to save name server group to the store: %s", err)
		return status.Errorf(status.Internal, "failed to save name server group to store")
	}
	return nil
}

// DeleteNameServerGroup deletes a name server group from the database.
func (s *SqlStore) DeleteNameServerGroup(ctx context.Context, accountID, nsGroupID string) error {
	result := s.db.Delete(&nbdns.NameServerGroup{}, accountAndIDQueryCondition, accountID, nsGroupID)
	if err := result.Error; err != nil {
		log.WithContext(ctx).Errorf("failed to delete name server group from the store: %s", err)
		return status.Errorf(status.Internal, "failed to delete name server group from store")
	}

	if result.RowsAffected == 0 {
		return status.NewNameServerGroupNotFoundError(nsGroupID)
	}

	return nil
}

// SaveDNSSettings saves the DNS settings to the store.
func (s *SqlStore) SaveDNSSettings(ctx context.Context, accountID string, settings *types.DNSSettings) error {
	result := s.db.Model(&types.Account{}).
		Where(idQueryCondition, accountID).Updates(&types.AccountDNSSettings{DNSSettings: *settings})
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to save dns settings to store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to save dns settings to store")
	}

	if result.RowsAffected == 0 {
		return status.NewAccountNotFoundError(accountID)
	}

	return nil
}

// SaveAccountSettings stores the account settings in DB.
func (s *SqlStore) SaveAccountSettings(ctx context.Context, accountID string, settings *types.Settings) error {
	result := s.db.Model(&types.Account{}).
		Select("*").Where(idQueryCondition, accountID).Updates(&types.AccountSettings{Settings: settings})
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to save account settings to store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to save account settings to store")
	}

	if result.RowsAffected == 0 {
		return status.NewAccountNotFoundError(accountID)
	}

	return nil
}

func (s *SqlStore) GetAccountNetworks(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*networkTypes.Network, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var networks []*networkTypes.Network
	result := tx.Find(&networks, accountIDCondition, accountID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get networks from the store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get networks from store")
	}

	return networks, nil
}

func (s *SqlStore) GetNetworkByID(ctx context.Context, lockStrength LockingStrength, accountID, networkID string) (*networkTypes.Network, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var network *networkTypes.Network
	result := tx.Take(&network, accountAndIDQueryCondition, accountID, networkID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.NewNetworkNotFoundError(networkID)
		}

		log.WithContext(ctx).Errorf("failed to get network from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get network from store")
	}

	return network, nil
}

func (s *SqlStore) SaveNetwork(ctx context.Context, network *networkTypes.Network) error {
	result := s.db.Save(network)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to save network to store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to save network to store")
	}

	return nil
}

func (s *SqlStore) DeleteNetwork(ctx context.Context, accountID, networkID string) error {
	result := s.db.Delete(&networkTypes.Network{}, accountAndIDQueryCondition, accountID, networkID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to delete network from store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to delete network from store")
	}

	if result.RowsAffected == 0 {
		return status.NewNetworkNotFoundError(networkID)
	}

	return nil
}

func (s *SqlStore) GetNetworkRoutersByNetID(ctx context.Context, lockStrength LockingStrength, accountID, netID string) ([]*routerTypes.NetworkRouter, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var netRouters []*routerTypes.NetworkRouter
	result := tx.
		Find(&netRouters, "account_id = ? AND network_id = ?", accountID, netID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get network routers from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get network routers from store")
	}

	return netRouters, nil
}

func (s *SqlStore) GetNetworkRoutersByAccountID(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*routerTypes.NetworkRouter, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var netRouters []*routerTypes.NetworkRouter
	result := tx.
		Find(&netRouters, accountIDCondition, accountID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get network routers from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get network routers from store")
	}

	return netRouters, nil
}

func (s *SqlStore) GetNetworkRouterByID(ctx context.Context, lockStrength LockingStrength, accountID, routerID string) (*routerTypes.NetworkRouter, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var netRouter *routerTypes.NetworkRouter
	result := tx.
		Take(&netRouter, accountAndIDQueryCondition, accountID, routerID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.NewNetworkRouterNotFoundError(routerID)
		}
		log.WithContext(ctx).Errorf("failed to get network router from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get network router from store")
	}

	return netRouter, nil
}

func (s *SqlStore) SaveNetworkRouter(ctx context.Context, router *routerTypes.NetworkRouter) error {
	result := s.db.Save(router)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to save network router to store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to save network router to store")
	}

	return nil
}

func (s *SqlStore) DeleteNetworkRouter(ctx context.Context, accountID, routerID string) error {
	result := s.db.Delete(&routerTypes.NetworkRouter{}, accountAndIDQueryCondition, accountID, routerID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to delete network router from store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to delete network router from store")
	}

	if result.RowsAffected == 0 {
		return status.NewNetworkRouterNotFoundError(routerID)
	}

	return nil
}

func (s *SqlStore) GetNetworkResourcesByNetID(ctx context.Context, lockStrength LockingStrength, accountID, networkID string) ([]*resourceTypes.NetworkResource, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var netResources []*resourceTypes.NetworkResource
	result := tx.
		Find(&netResources, "account_id = ? AND network_id = ?", accountID, networkID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get network resources from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get network resources from store")
	}

	return netResources, nil
}

func (s *SqlStore) GetNetworkResourcesByAccountID(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*resourceTypes.NetworkResource, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var netResources []*resourceTypes.NetworkResource
	result := tx.
		Find(&netResources, accountIDCondition, accountID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get network resources from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get network resources from store")
	}

	return netResources, nil
}

func (s *SqlStore) GetNetworkResourceByID(ctx context.Context, lockStrength LockingStrength, accountID, resourceID string) (*resourceTypes.NetworkResource, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var netResources *resourceTypes.NetworkResource
	result := tx.
		Take(&netResources, accountAndIDQueryCondition, accountID, resourceID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.NewNetworkResourceNotFoundError(resourceID)
		}
		log.WithContext(ctx).Errorf("failed to get network resource from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get network resource from store")
	}

	return netResources, nil
}

func (s *SqlStore) GetNetworkResourceByName(ctx context.Context, lockStrength LockingStrength, accountID, resourceName string) (*resourceTypes.NetworkResource, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var netResources *resourceTypes.NetworkResource
	result := tx.
		Take(&netResources, "account_id = ? AND name = ?", accountID, resourceName)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.NewNetworkResourceNotFoundError(resourceName)
		}
		log.WithContext(ctx).Errorf("failed to get network resource from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get network resource from store")
	}

	return netResources, nil
}

func (s *SqlStore) SaveNetworkResource(ctx context.Context, resource *resourceTypes.NetworkResource) error {
	result := s.db.Save(resource)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to save network resource to store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to save network resource to store")
	}

	return nil
}

func (s *SqlStore) DeleteNetworkResource(ctx context.Context, accountID, resourceID string) error {
	result := s.db.Delete(&resourceTypes.NetworkResource{}, accountAndIDQueryCondition, accountID, resourceID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to delete network resource from store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to delete network resource from store")
	}

	if result.RowsAffected == 0 {
		return status.NewNetworkResourceNotFoundError(resourceID)
	}

	return nil
}

// GetPATByHashedToken returns a PersonalAccessToken by its hashed token.
func (s *SqlStore) GetPATByHashedToken(ctx context.Context, lockStrength LockingStrength, hashedToken string) (*types.PersonalAccessToken, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var pat types.PersonalAccessToken
	result := tx.Take(&pat, "hashed_token = ?", hashedToken)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.NewPATNotFoundError(hashedToken)
		}
		log.WithContext(ctx).Errorf("failed to get pat by hash from the store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get pat by hash from store")
	}

	return &pat, nil
}

// GetPATByID retrieves a personal access token by its ID and user ID.
func (s *SqlStore) GetPATByID(ctx context.Context, lockStrength LockingStrength, userID string, patID string) (*types.PersonalAccessToken, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var pat types.PersonalAccessToken
	result := tx.
		Take(&pat, "id = ? AND user_id = ?", patID, userID)
	if err := result.Error; err != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.NewPATNotFoundError(patID)
		}
		log.WithContext(ctx).Errorf("failed to get pat from the store: %s", err)
		return nil, status.Errorf(status.Internal, "failed to get pat from store")
	}

	return &pat, nil
}

// GetUserPATs retrieves personal access tokens for a user.
func (s *SqlStore) GetUserPATs(ctx context.Context, lockStrength LockingStrength, userID string) ([]*types.PersonalAccessToken, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var pats []*types.PersonalAccessToken
	result := tx.Find(&pats, "user_id = ?", userID)
	if err := result.Error; err != nil {
		log.WithContext(ctx).Errorf("failed to get user pat's from the store: %s", err)
		return nil, status.Errorf(status.Internal, "failed to get user pat's from store")
	}

	return pats, nil
}

// MarkPATUsed marks a personal access token as used.
func (s *SqlStore) MarkPATUsed(ctx context.Context, patID string) error {
	patCopy := types.PersonalAccessToken{
		LastUsed: util.ToPtr(time.Now().UTC()),
	}

	fieldsToUpdate := []string{"last_used"}
	result := s.db.Select(fieldsToUpdate).
		Where(idQueryCondition, patID).Updates(&patCopy)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to mark pat as used: %s", result.Error)
		return status.Errorf(status.Internal, "failed to mark pat as used")
	}

	if result.RowsAffected == 0 {
		return status.NewPATNotFoundError(patID)
	}

	return nil
}

// SavePAT saves a personal access token to the database.
func (s *SqlStore) SavePAT(ctx context.Context, pat *types.PersonalAccessToken) error {
	result := s.db.Save(pat)
	if err := result.Error; err != nil {
		log.WithContext(ctx).Errorf("failed to save pat to the store: %s", err)
		return status.Errorf(status.Internal, "failed to save pat to store")
	}

	return nil
}

// DeletePAT deletes a personal access token from the database.
func (s *SqlStore) DeletePAT(ctx context.Context, userID, patID string) error {
	result := s.db.Delete(&types.PersonalAccessToken{}, "user_id = ? AND id = ?", userID, patID)
	if err := result.Error; err != nil {
		log.WithContext(ctx).Errorf("failed to delete pat from the store: %s", err)
		return status.Errorf(status.Internal, "failed to delete pat from store")
	}

	if result.RowsAffected == 0 {
		return status.NewPATNotFoundError(patID)
	}

	return nil
}

func (s *SqlStore) GetPeerByIP(ctx context.Context, lockStrength LockingStrength, accountID string, ip net.IP) (*nbpeer.Peer, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	jsonValue := fmt.Sprintf(`"%s"`, ip.String())

	var peer nbpeer.Peer
	result := tx.
		Take(&peer, "account_id = ? AND ip = ?", accountID, jsonValue)
	if result.Error != nil {
		// no logging here
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

func (s *SqlStore) CountAccountsByPrivateDomain(ctx context.Context, domain string) (int64, error) {
	var count int64
	result := s.db.Model(&types.Account{}).
		Where("domain = ? AND domain_category = ?",
			strings.ToLower(domain), types.PrivateCategory,
		).Count(&count)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to count accounts by private domain %s: %s", domain, result.Error)
		return 0, status.Errorf(status.Internal, "failed to count accounts by private domain")
	}

	return count, nil
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

func (s *SqlStore) IsPrimaryAccount(ctx context.Context, accountID string) (bool, string, error) {
	var info types.PrimaryAccountInfo
	result := s.db.Model(&types.Account{}).
		Select("is_domain_primary_account, domain").
		Where(idQueryCondition, accountID).
		Take(&info)

	if result.Error != nil {
		return false, "", status.Errorf(status.Internal, "failed to get account info: %v", result.Error)
	}

	return info.IsDomainPrimaryAccount, info.Domain, nil
}

func (s *SqlStore) MarkAccountPrimary(ctx context.Context, accountID string) error {
	result := s.db.Model(&types.Account{}).
		Where(idQueryCondition, accountID).
		Update("is_domain_primary_account", true)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to mark account as primary: %s", result.Error)
		return status.Errorf(status.Internal, "failed to mark account as primary")
	}

	if result.RowsAffected == 0 {
		return status.NewAccountNotFoundError(accountID)
	}

	return nil
}

type accountNetworkPatch struct {
	Network *types.Network `gorm:"embedded;embeddedPrefix:network_"`
}

func (s *SqlStore) UpdateAccountNetwork(ctx context.Context, accountID string, ipNet net.IPNet) error {
	patch := accountNetworkPatch{
		Network: &types.Network{Net: ipNet},
	}

	result := s.db.
		Model(&types.Account{}).
		Where(idQueryCondition, accountID).
		Updates(&patch)

	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to update account network: %v", result.Error)
		return status.Errorf(status.Internal, "failed to update account network")
	}
	if result.RowsAffected == 0 {
		return status.NewAccountNotFoundError(accountID)
	}
	return nil
}

func (s *SqlStore) GetPeersByGroupIDs(ctx context.Context, accountID string, groupIDs []string) ([]*nbpeer.Peer, error) {
	if len(groupIDs) == 0 {
		return []*nbpeer.Peer{}, nil
	}

	var peers []*nbpeer.Peer
	peerIDsSubquery := s.db.Model(&types.GroupPeer{}).
		Select("DISTINCT peer_id").
		Where("account_id = ? AND group_id IN ?", accountID, groupIDs)

	result := s.db.Where("id IN (?)", peerIDsSubquery).Find(&peers)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get peers by group IDs: %s", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get peers by group IDs")
	}

	return peers, nil
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

func (s *SqlStore) CreateZone(ctx context.Context, zone *zones.Zone) error {
	result := s.db.Create(zone)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to create zone to store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to create zone to store")
	}

	return nil
}

func (s *SqlStore) UpdateZone(ctx context.Context, zone *zones.Zone) error {
	result := s.db.Select("*").Save(zone)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to update zone to store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to update zone to store")
	}

	return nil
}

func (s *SqlStore) DeleteZone(ctx context.Context, accountID, zoneID string) error {
	result := s.db.Delete(&zones.Zone{}, accountAndIDQueryCondition, accountID, zoneID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to delete zone from store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to delete zone from store")
	}

	if result.RowsAffected == 0 {
		return status.NewZoneNotFoundError(zoneID)
	}

	return nil
}

func (s *SqlStore) GetZoneByID(ctx context.Context, lockStrength LockingStrength, accountID, zoneID string) (*zones.Zone, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var zone *zones.Zone
	result := tx.Preload("Records").Take(&zone, accountAndIDQueryCondition, accountID, zoneID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.NewZoneNotFoundError(zoneID)
		}

		log.WithContext(ctx).Errorf("failed to get zone from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get zone from store")
	}

	return zone, nil
}

func (s *SqlStore) GetZoneByDomain(ctx context.Context, accountID, domain string) (*zones.Zone, error) {
	var zone *zones.Zone
	result := s.db.Where("account_id = ? AND domain = ?", accountID, domain).First(&zone)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.NewZoneNotFoundError(domain)
		}

		log.WithContext(ctx).Errorf("failed to get zone by domain from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get zone by domain from store")
	}

	return zone, nil
}

func (s *SqlStore) GetAccountZones(ctx context.Context, lockStrength LockingStrength, accountID string) ([]*zones.Zone, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var zones []*zones.Zone
	result := tx.Preload("Records").Find(&zones, accountIDCondition, accountID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get zones from the store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get zones from store")
	}

	return zones, nil
}

func (s *SqlStore) CreateDNSRecord(ctx context.Context, record *records.Record) error {
	result := s.db.Create(record)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to create dns record to store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to create dns record to store")
	}

	return nil
}

func (s *SqlStore) UpdateDNSRecord(ctx context.Context, record *records.Record) error {
	result := s.db.Select("*").Save(record)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to update dns record to store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to update dns record to store")
	}

	return nil
}

func (s *SqlStore) DeleteDNSRecord(ctx context.Context, accountID, zoneID, recordID string) error {
	result := s.db.Delete(&records.Record{}, "account_id = ? AND zone_id = ? AND id = ?", accountID, zoneID, recordID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to delete dns record from store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to delete dns record from store")
	}

	if result.RowsAffected == 0 {
		return status.NewDNSRecordNotFoundError(recordID)
	}

	return nil
}

func (s *SqlStore) GetDNSRecordByID(ctx context.Context, lockStrength LockingStrength, accountID, zoneID, recordID string) (*records.Record, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var record *records.Record
	result := tx.Where("account_id = ? AND zone_id = ? AND id = ?", accountID, zoneID, recordID).Take(&record)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, status.NewDNSRecordNotFoundError(recordID)
		}

		log.WithContext(ctx).Errorf("failed to get dns record from store: %v", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get dns record from store")
	}

	return record, nil
}

func (s *SqlStore) GetZoneDNSRecords(ctx context.Context, lockStrength LockingStrength, accountID, zoneID string) ([]*records.Record, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var recordsList []*records.Record
	result := tx.Where("account_id = ? AND zone_id = ?", accountID, zoneID).Find(&recordsList)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get zone dns records from the store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get zone dns records from store")
	}

	return recordsList, nil
}

func (s *SqlStore) GetZoneDNSRecordsByName(ctx context.Context, lockStrength LockingStrength, accountID, zoneID, name string) ([]*records.Record, error) {
	tx := s.db
	if lockStrength != LockingStrengthNone {
		tx = tx.Clauses(clause.Locking{Strength: string(lockStrength)})
	}

	var recordsList []*records.Record
	result := tx.Where("account_id = ? AND zone_id = ? AND name = ?", accountID, zoneID, name).Find(&recordsList)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to get zone dns records by name from the store: %s", result.Error)
		return nil, status.Errorf(status.Internal, "failed to get zone dns records by name from store")
	}

	return recordsList, nil
}

func (s *SqlStore) DeleteZoneDNSRecords(ctx context.Context, accountID, zoneID string) error {
	result := s.db.Delete(&records.Record{}, "account_id = ? AND zone_id = ?", accountID, zoneID)
	if result.Error != nil {
		log.WithContext(ctx).Errorf("failed to delete zone dns records from store: %v", result.Error)
		return status.Errorf(status.Internal, "failed to delete zone dns records from store")
	}

	return nil
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
