package server

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"

	nbgroup "github.com/netbirdio/netbird/management/server/group"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/status"
	"github.com/netbirdio/netbird/management/server/telemetry"

	"github.com/netbirdio/netbird/util"
)

// storeFileName Store file name. Stored in the datadir
const storeFileName = "store.json"

// FileStore represents an account storage backed by a file persisted to disk
type FileStore struct {
	Accounts                map[string]*Account
	SetupKeyID2AccountID    map[string]string `json:"-"`
	PeerKeyID2AccountID     map[string]string `json:"-"`
	PeerID2AccountID        map[string]string `json:"-"`
	UserID2AccountID        map[string]string `json:"-"`
	PrivateDomain2AccountID map[string]string `json:"-"`
	HashedPAT2TokenID       map[string]string `json:"-"`
	TokenID2UserID          map[string]string `json:"-"`
	InstallationID          string

	// mutex to synchronise Store read/write operations
	mux       sync.Mutex `json:"-"`
	storeFile string     `json:"-"`

	// sync.Mutex indexed by resource ID
	resourceLocks     sync.Map   `json:"-"`
	globalAccountLock sync.Mutex `json:"-"`

	metrics telemetry.AppMetrics `json:"-"`
}

type StoredAccount struct{}

// NewFileStore restores a store from the file located in the datadir
func NewFileStore(ctx context.Context, dataDir string, metrics telemetry.AppMetrics) (*FileStore, error) {
	fs, err := restore(ctx, filepath.Join(dataDir, storeFileName))
	if err != nil {
		return nil, err
	}
	fs.metrics = metrics
	return fs, nil
}

// NewFilestoreFromSqliteStore restores a store from Sqlite and stores to Filestore json in the file located in datadir
func NewFilestoreFromSqliteStore(ctx context.Context, sqlStore *SqlStore, dataDir string, metrics telemetry.AppMetrics) (*FileStore, error) {
	store, err := NewFileStore(ctx, dataDir, metrics)
	if err != nil {
		return nil, err
	}

	err = store.SaveInstallationID(ctx, sqlStore.GetInstallationID())
	if err != nil {
		return nil, err
	}

	for _, account := range sqlStore.GetAllAccounts(ctx) {
		store.Accounts[account.Id] = account
	}

	return store, store.persist(ctx, store.storeFile)
}

// restore the state of the store from the file.
// Creates a new empty store file if doesn't exist
func restore(ctx context.Context, file string) (*FileStore, error) {
	if _, err := os.Stat(file); os.IsNotExist(err) {
		// create a new FileStore if previously didn't exist (e.g. first run)
		s := &FileStore{
			Accounts:                make(map[string]*Account),
			mux:                     sync.Mutex{},
			globalAccountLock:       sync.Mutex{},
			SetupKeyID2AccountID:    make(map[string]string),
			PeerKeyID2AccountID:     make(map[string]string),
			UserID2AccountID:        make(map[string]string),
			PrivateDomain2AccountID: make(map[string]string),
			PeerID2AccountID:        make(map[string]string),
			HashedPAT2TokenID:       make(map[string]string),
			TokenID2UserID:          make(map[string]string),
			storeFile:               file,
		}

		err = s.persist(ctx, file)
		if err != nil {
			return nil, err
		}

		return s, nil
	}

	read, err := util.ReadJson(file, &FileStore{})
	if err != nil {
		return nil, err
	}

	store := read.(*FileStore)
	store.storeFile = file
	store.SetupKeyID2AccountID = make(map[string]string)
	store.PeerKeyID2AccountID = make(map[string]string)
	store.UserID2AccountID = make(map[string]string)
	store.PrivateDomain2AccountID = make(map[string]string)
	store.PeerID2AccountID = make(map[string]string)
	store.HashedPAT2TokenID = make(map[string]string)
	store.TokenID2UserID = make(map[string]string)

	for accountID, account := range store.Accounts {
		if account.Settings == nil {
			account.Settings = &Settings{
				PeerLoginExpirationEnabled: false,
				PeerLoginExpiration:        DefaultPeerLoginExpiration,

				PeerInactivityExpirationEnabled: false,
				PeerInactivityExpiration:        DefaultPeerInactivityExpiration,
			}
		}

		for setupKeyId := range account.SetupKeys {
			store.SetupKeyID2AccountID[strings.ToUpper(setupKeyId)] = accountID
		}

		for _, peer := range account.Peers {
			store.PeerKeyID2AccountID[peer.Key] = accountID
			store.PeerID2AccountID[peer.ID] = accountID
		}
		for _, user := range account.Users {
			store.UserID2AccountID[user.Id] = accountID
			if user.Issued == "" {
				user.Issued = UserIssuedAPI
				account.Users[user.Id] = user
			}

			for _, pat := range user.PATs {
				store.TokenID2UserID[pat.ID] = user.Id
				store.HashedPAT2TokenID[pat.HashedToken] = pat.ID
			}
		}

		if account.Domain != "" && account.DomainCategory == PrivateCategory &&
			account.IsDomainPrimaryAccount {
			store.PrivateDomain2AccountID[account.Domain] = accountID
		}

		// TODO: delete this block after migration
		policies := make(map[string]int, len(account.Policies))
		for i, policy := range account.Policies {
			policies[policy.ID] = i
			policy.UpgradeAndFix()
		}
		if account.Policies == nil {
			account.Policies = make([]*Policy, 0)
		}

		// for data migration. Can be removed once most base will be with labels
		existingLabels := account.getPeerDNSLabels()
		if len(existingLabels) != len(account.Peers) {
			addPeerLabelsToAccount(ctx, account, existingLabels)
		}

		// TODO: delete this block after migration
		// Set API as issuer for groups which has not this field
		for _, group := range account.Groups {
			if group.Issued == "" {
				group.Issued = nbgroup.GroupIssuedAPI
			}
		}

		allGroup, err := account.GetGroupAll()
		if err != nil {
			log.WithContext(ctx).Errorf("unable to find the All group, this should happen only when migrate from a version that didn't support groups. Error: %v", err)
			// if the All group didn't exist we probably don't have routes to update
			continue
		}

		for _, route := range account.Routes {
			if len(route.Groups) == 0 {
				route.Groups = []string{allGroup.ID}
			}
		}

		// migration to Peer.ID from Peer.Key.
		// Old peers that require migration have an empty Peer.ID in the store.json.
		// Generate new ID with xid for these peers.
		// Set the Peer.ID to the newly generated value.
		// Replace all the mentions of Peer.Key as ID (groups and routes).
		// Swap Peer.Key with Peer.ID in the Account.Peers map.
		migrationPeers := make(map[string]*nbpeer.Peer) // key to Peer
		for key, peer := range account.Peers {
			// set LastLogin for the peers that were onboarded before the peer login expiration feature
			if peer.LastLogin.IsZero() {
				peer.LastLogin = time.Now().UTC()
			}
			if peer.ID != "" {
				continue
			}
			id := xid.New().String()
			peer.ID = id
			migrationPeers[key] = peer
		}

		if len(migrationPeers) > 0 {
			// swap Peer.Key with Peer.ID in the Account.Peers map.
			for key, peer := range migrationPeers {
				delete(account.Peers, key)
				account.Peers[peer.ID] = peer
				store.PeerID2AccountID[peer.ID] = accountID
			}

			// detect groups that have Peer.Key as a reference and replace it with ID.
			for _, group := range account.Groups {
				for i, peer := range group.Peers {
					if p, ok := migrationPeers[peer]; ok {
						group.Peers[i] = p.ID
					}
				}
			}

			// detect routes that have Peer.Key as a reference and replace it with ID.
			for _, route := range account.Routes {
				if peer, ok := migrationPeers[route.Peer]; ok {
					route.Peer = peer.ID
				}
			}
		}
	}

	// we need this persist to apply changes we made to account.Peers (we set them to Disconnected)
	err = store.persist(ctx, store.storeFile)
	if err != nil {
		return nil, err
	}

	return store, nil
}

// persist account data to a file
// It is recommended to call it with locking FileStore.mux
func (s *FileStore) persist(ctx context.Context, file string) error {
	start := time.Now()
	err := util.WriteJson(file, s)
	if err != nil {
		return err
	}
	took := time.Since(start)
	if s.metrics != nil {
		s.metrics.StoreMetrics().CountPersistenceDuration(took)
	}
	log.WithContext(ctx).Debugf("took %d ms to persist the FileStore", took.Milliseconds())
	return nil
}

// AcquireGlobalLock acquires global lock across all the accounts and returns a function that releases the lock
func (s *FileStore) AcquireGlobalLock(ctx context.Context) (unlock func()) {
	log.WithContext(ctx).Debugf("acquiring global lock")
	start := time.Now()
	s.globalAccountLock.Lock()

	unlock = func() {
		s.globalAccountLock.Unlock()
		log.WithContext(ctx).Debugf("released global lock in %v", time.Since(start))
	}

	took := time.Since(start)
	log.WithContext(ctx).Debugf("took %v to acquire global lock", took)
	if s.metrics != nil {
		s.metrics.StoreMetrics().CountGlobalLockAcquisitionDuration(took)
	}

	return unlock
}

// AcquireWriteLockByUID acquires an ID lock for writing to a resource and returns a function that releases the lock
func (s *FileStore) AcquireWriteLockByUID(ctx context.Context, uniqueID string) (unlock func()) {
	log.WithContext(ctx).Debugf("acquiring lock for ID %s", uniqueID)
	start := time.Now()
	value, _ := s.resourceLocks.LoadOrStore(uniqueID, &sync.Mutex{})
	mtx := value.(*sync.Mutex)
	mtx.Lock()

	unlock = func() {
		mtx.Unlock()
		log.WithContext(ctx).Debugf("released lock for ID %s in %v", uniqueID, time.Since(start))
	}

	return unlock
}

// AcquireReadLockByUID acquires an ID lock for reading a resource and returns a function that releases the lock
// This method is still returns a write lock as file store can't handle read locks
func (s *FileStore) AcquireReadLockByUID(ctx context.Context, uniqueID string) (unlock func()) {
	return s.AcquireWriteLockByUID(ctx, uniqueID)
}

func (s *FileStore) SaveAccount(ctx context.Context, account *Account) error {
	s.mux.Lock()
	defer s.mux.Unlock()

	if account.Id == "" {
		return status.Errorf(status.InvalidArgument, "account id should not be empty")
	}

	accountCopy := account.Copy()

	s.Accounts[accountCopy.Id] = accountCopy

	// todo check that account.Id and keyId are not exist already
	// because if keyId exists for other accounts this can be bad
	for keyID := range accountCopy.SetupKeys {
		s.SetupKeyID2AccountID[strings.ToUpper(keyID)] = accountCopy.Id
	}

	// enforce peer to account index and delete peer to route indexes for rebuild
	for _, peer := range accountCopy.Peers {
		s.PeerKeyID2AccountID[peer.Key] = accountCopy.Id
		s.PeerID2AccountID[peer.ID] = accountCopy.Id
	}

	for _, user := range accountCopy.Users {
		s.UserID2AccountID[user.Id] = accountCopy.Id
		for _, pat := range user.PATs {
			s.TokenID2UserID[pat.ID] = user.Id
			s.HashedPAT2TokenID[pat.HashedToken] = pat.ID
		}
	}

	if accountCopy.DomainCategory == PrivateCategory && accountCopy.IsDomainPrimaryAccount {
		s.PrivateDomain2AccountID[accountCopy.Domain] = accountCopy.Id
	}

	return s.persist(ctx, s.storeFile)
}

func (s *FileStore) DeleteAccount(ctx context.Context, account *Account) error {
	s.mux.Lock()
	defer s.mux.Unlock()

	if account.Id == "" {
		return status.Errorf(status.InvalidArgument, "account id should not be empty")
	}

	for keyID := range account.SetupKeys {
		delete(s.SetupKeyID2AccountID, strings.ToUpper(keyID))
	}

	// enforce peer to account index and delete peer to route indexes for rebuild
	for _, peer := range account.Peers {
		delete(s.PeerKeyID2AccountID, peer.Key)
		delete(s.PeerID2AccountID, peer.ID)
	}

	for _, user := range account.Users {
		for _, pat := range user.PATs {
			delete(s.TokenID2UserID, pat.ID)
			delete(s.HashedPAT2TokenID, pat.HashedToken)
		}
		delete(s.UserID2AccountID, user.Id)
	}

	if account.DomainCategory == PrivateCategory && account.IsDomainPrimaryAccount {
		delete(s.PrivateDomain2AccountID, account.Domain)
	}

	delete(s.Accounts, account.Id)

	return s.persist(ctx, s.storeFile)
}

// DeleteHashedPAT2TokenIDIndex removes an entry from the indexing map HashedPAT2TokenID
func (s *FileStore) DeleteHashedPAT2TokenIDIndex(hashedToken string) error {
	s.mux.Lock()
	defer s.mux.Unlock()

	delete(s.HashedPAT2TokenID, hashedToken)

	return nil
}

// DeleteTokenID2UserIDIndex removes an entry from the indexing map TokenID2UserID
func (s *FileStore) DeleteTokenID2UserIDIndex(tokenID string) error {
	s.mux.Lock()
	defer s.mux.Unlock()

	delete(s.TokenID2UserID, tokenID)

	return nil
}

// GetAccountByPrivateDomain returns account by private domain
func (s *FileStore) GetAccountByPrivateDomain(_ context.Context, domain string) (*Account, error) {
	s.mux.Lock()
	defer s.mux.Unlock()

	accountID, ok := s.PrivateDomain2AccountID[strings.ToLower(domain)]
	if !ok {
		return nil, status.Errorf(status.NotFound, "account not found: provided domain is not registered or is not private")
	}

	account, err := s.getAccount(accountID)
	if err != nil {
		return nil, err
	}

	return account.Copy(), nil
}

// GetAccountBySetupKey returns account by setup key id
func (s *FileStore) GetAccountBySetupKey(_ context.Context, setupKey string) (*Account, error) {
	s.mux.Lock()
	defer s.mux.Unlock()

	accountID, ok := s.SetupKeyID2AccountID[strings.ToUpper(setupKey)]
	if !ok {
		return nil, status.Errorf(status.NotFound, "account not found: provided setup key doesn't exists")
	}

	account, err := s.getAccount(accountID)
	if err != nil {
		return nil, err
	}

	return account.Copy(), nil
}

// GetTokenIDByHashedToken returns the id of a personal access token by its hashed secret
func (s *FileStore) GetTokenIDByHashedToken(_ context.Context, token string) (string, error) {
	s.mux.Lock()
	defer s.mux.Unlock()

	tokenID, ok := s.HashedPAT2TokenID[token]
	if !ok {
		return "", status.Errorf(status.NotFound, "tokenID not found: provided token doesn't exists")
	}

	return tokenID, nil
}

// GetUserByTokenID returns a User object a tokenID belongs to
func (s *FileStore) GetUserByTokenID(_ context.Context, tokenID string) (*User, error) {
	s.mux.Lock()
	defer s.mux.Unlock()

	userID, ok := s.TokenID2UserID[tokenID]
	if !ok {
		return nil, status.Errorf(status.NotFound, "user not found: provided tokenID doesn't exists")
	}

	accountID, ok := s.UserID2AccountID[userID]
	if !ok {
		return nil, status.Errorf(status.NotFound, "accountID not found: provided userID doesn't exists")
	}

	account, err := s.getAccount(accountID)
	if err != nil {
		return nil, err
	}

	return account.Users[userID].Copy(), nil
}

func (s *FileStore) GetUserByUserID(_ context.Context, userID string) (*User, error) {
	accountID, ok := s.UserID2AccountID[userID]
	if !ok {
		return nil, status.Errorf(status.NotFound, "accountID not found: provided userID doesn't exists")
	}

	account, err := s.getAccount(accountID)
	if err != nil {
		return nil, err
	}

	return account.Users[userID].Copy(), nil
}

func (s *FileStore) GetAccountGroups(ctx context.Context, accountID string) ([]*nbgroup.Group, error) {
	account, err := s.getAccount(accountID)
	if err != nil {
		return nil, err
	}

	groupsSlice := make([]*nbgroup.Group, 0, len(account.Groups))

	for _, group := range account.Groups {
		groupsSlice = append(groupsSlice, group)
	}

	return groupsSlice, nil
}

// GetAllAccounts returns all accounts
func (s *FileStore) GetAllAccounts(_ context.Context) (all []*Account) {
	s.mux.Lock()
	defer s.mux.Unlock()
	for _, a := range s.Accounts {
		all = append(all, a.Copy())
	}

	return all
}

// getAccount returns a reference to the Account. Should not return a copy.
func (s *FileStore) getAccount(accountID string) (*Account, error) {
	account, ok := s.Accounts[accountID]
	if !ok {
		return nil, status.Errorf(status.NotFound, "account not found")
	}

	return account, nil
}

// GetAccount returns an account for ID
func (s *FileStore) GetAccount(_ context.Context, accountID string) (*Account, error) {
	s.mux.Lock()
	defer s.mux.Unlock()

	account, err := s.getAccount(accountID)
	if err != nil {
		return nil, err
	}

	return account.Copy(), nil
}

// GetAccountByUser returns a user account
func (s *FileStore) GetAccountByUser(_ context.Context, userID string) (*Account, error) {
	s.mux.Lock()
	defer s.mux.Unlock()

	accountID, ok := s.UserID2AccountID[userID]
	if !ok {
		return nil, status.NewUserNotFoundError(userID)
	}

	account, err := s.getAccount(accountID)
	if err != nil {
		return nil, err
	}

	return account.Copy(), nil
}

// GetAccountByPeerID returns an account for a given peer ID
func (s *FileStore) GetAccountByPeerID(ctx context.Context, peerID string) (*Account, error) {
	s.mux.Lock()
	defer s.mux.Unlock()

	accountID, ok := s.PeerID2AccountID[peerID]
	if !ok {
		return nil, status.Errorf(status.NotFound, "provided peer ID doesn't exists %s", peerID)
	}

	account, err := s.getAccount(accountID)
	if err != nil {
		return nil, err
	}

	// this protection is needed because when we delete a peer, we don't really remove index peerID -> accountID.
	// check Account.Peers for a match
	if _, ok := account.Peers[peerID]; !ok {
		delete(s.PeerID2AccountID, peerID)
		log.WithContext(ctx).Warnf("removed stale peerID %s to accountID %s index", peerID, accountID)
		return nil, status.NewPeerNotFoundError(peerID)
	}

	return account.Copy(), nil
}

// GetAccountByPeerPubKey returns an account for a given peer WireGuard public key
func (s *FileStore) GetAccountByPeerPubKey(ctx context.Context, peerKey string) (*Account, error) {
	s.mux.Lock()
	defer s.mux.Unlock()

	accountID, ok := s.PeerKeyID2AccountID[peerKey]
	if !ok {
		return nil, status.NewPeerNotFoundError(peerKey)
	}

	account, err := s.getAccount(accountID)
	if err != nil {
		return nil, err
	}

	// this protection is needed because when we delete a peer, we don't really remove index peerKey -> accountID.
	// check Account.Peers for a match
	stale := true
	for _, peer := range account.Peers {
		if peer.Key == peerKey {
			stale = false
			break
		}
	}
	if stale {
		delete(s.PeerKeyID2AccountID, peerKey)
		log.WithContext(ctx).Warnf("removed stale peerKey %s to accountID %s index", peerKey, accountID)
		return nil, status.NewPeerNotFoundError(peerKey)
	}

	return account.Copy(), nil
}

func (s *FileStore) GetAccountIDByPeerPubKey(_ context.Context, peerKey string) (string, error) {
	s.mux.Lock()
	defer s.mux.Unlock()

	accountID, ok := s.PeerKeyID2AccountID[peerKey]
	if !ok {
		return "", status.NewPeerNotFoundError(peerKey)
	}

	return accountID, nil
}

func (s *FileStore) GetAccountIDByUserID(userID string) (string, error) {
	s.mux.Lock()
	defer s.mux.Unlock()

	accountID, ok := s.UserID2AccountID[userID]
	if !ok {
		return "", status.NewUserNotFoundError(userID)
	}

	return accountID, nil
}

func (s *FileStore) GetAccountIDBySetupKey(_ context.Context, setupKey string) (string, error) {
	s.mux.Lock()
	defer s.mux.Unlock()

	accountID, ok := s.SetupKeyID2AccountID[strings.ToUpper(setupKey)]
	if !ok {
		return "", status.Errorf(status.NotFound, "account not found: provided setup key doesn't exists")
	}

	return accountID, nil
}

func (s *FileStore) GetPeerByPeerPubKey(_ context.Context, peerKey string) (*nbpeer.Peer, error) {
	s.mux.Lock()
	defer s.mux.Unlock()

	accountID, ok := s.PeerKeyID2AccountID[peerKey]
	if !ok {
		return nil, status.NewPeerNotFoundError(peerKey)
	}

	account, err := s.getAccount(accountID)
	if err != nil {
		return nil, err
	}

	for _, peer := range account.Peers {
		if peer.Key == peerKey {
			return peer.Copy(), nil
		}
	}

	return nil, status.NewPeerNotFoundError(peerKey)
}

func (s *FileStore) GetAccountSettings(_ context.Context, accountID string) (*Settings, error) {
	s.mux.Lock()
	defer s.mux.Unlock()

	account, err := s.getAccount(accountID)
	if err != nil {
		return nil, err
	}

	return account.Settings.Copy(), nil
}

// GetInstallationID returns the installation ID from the store
func (s *FileStore) GetInstallationID() string {
	return s.InstallationID
}

// SaveInstallationID saves the installation ID
func (s *FileStore) SaveInstallationID(ctx context.Context, ID string) error {
	s.mux.Lock()
	defer s.mux.Unlock()

	s.InstallationID = ID

	return s.persist(ctx, s.storeFile)
}

// SavePeer saves the peer in the account
func (s *FileStore) SavePeer(_ context.Context, accountID string, peer *nbpeer.Peer) error {
	s.mux.Lock()
	defer s.mux.Unlock()

	account, err := s.getAccount(accountID)
	if err != nil {
		return err
	}

	newPeer := peer.Copy()

	account.Peers[peer.ID] = newPeer

	s.PeerKeyID2AccountID[peer.Key] = accountID
	s.PeerID2AccountID[peer.ID] = accountID

	return nil
}

// SavePeerStatus stores the PeerStatus in memory. It doesn't attempt to persist data to speed up things.
// PeerStatus will be saved eventually when some other changes occur.
func (s *FileStore) SavePeerStatus(accountID, peerID string, peerStatus nbpeer.PeerStatus) error {
	s.mux.Lock()
	defer s.mux.Unlock()

	account, err := s.getAccount(accountID)
	if err != nil {
		return err
	}

	peer := account.Peers[peerID]
	if peer == nil {
		return status.Errorf(status.NotFound, "peer %s not found", peerID)
	}

	peer.Status = &peerStatus

	return nil
}

// SavePeerLocation stores the PeerStatus in memory. It doesn't attempt to persist data to speed up things.
// Peer.Location will be saved eventually when some other changes occur.
func (s *FileStore) SavePeerLocation(accountID string, peerWithLocation *nbpeer.Peer) error {
	s.mux.Lock()
	defer s.mux.Unlock()

	account, err := s.getAccount(accountID)
	if err != nil {
		return err
	}

	peer := account.Peers[peerWithLocation.ID]
	if peer == nil {
		return status.Errorf(status.NotFound, "peer %s not found", peerWithLocation.ID)
	}

	peer.Location = peerWithLocation.Location

	return nil
}

// SaveUserLastLogin stores the last login time for a user in memory. It doesn't attempt to persist data to speed up things.
func (s *FileStore) SaveUserLastLogin(accountID, userID string, lastLogin time.Time) error {
	s.mux.Lock()
	defer s.mux.Unlock()

	account, err := s.getAccount(accountID)
	if err != nil {
		return err
	}

	peer := account.Users[userID]
	if peer == nil {
		return status.Errorf(status.NotFound, "user %s not found", userID)
	}

	peer.LastLogin = lastLogin

	return nil
}

func (s *FileStore) GetPostureCheckByChecksDefinition(accountID string, checks *posture.ChecksDefinition) (*posture.Checks, error) {
	return nil, status.Errorf(status.Internal, "GetPostureCheckByChecksDefinition is not implemented")
}

// Close the FileStore persisting data to disk
func (s *FileStore) Close(ctx context.Context) error {
	s.mux.Lock()
	defer s.mux.Unlock()

	log.WithContext(ctx).Infof("closing FileStore")

	return s.persist(ctx, s.storeFile)
}

// GetStoreEngine returns FileStoreEngine
func (s *FileStore) GetStoreEngine() StoreEngine {
	return FileStoreEngine
}

func (s *FileStore) SaveUsers(accountID string, users map[string]*User) error {
	return status.Errorf(status.Internal, "SaveUsers is not implemented")
}

func (s *FileStore) SaveGroups(accountID string, groups map[string]*nbgroup.Group) error {
	return status.Errorf(status.Internal, "SaveGroups is not implemented")
}
