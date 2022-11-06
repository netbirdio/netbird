package server

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/util"
)

// storeFileName Store file name. Stored in the datadir
const storeFileName = "store.json"

// FileStore represents an account storage backed by a file persisted to disk
type FileStore struct {
	Accounts                map[string]*Account
	SetupKeyID2AccountID    map[string]string `json:"-"`
	PeerKeyID2AccountID     map[string]string `json:"-"`
	UserID2AccountID        map[string]string `json:"-"`
	PrivateDomain2AccountID map[string]string `json:"-"`
	InstallationID          string

	// mutex to synchronise Store read/write operations
	mux       sync.Mutex `json:"-"`
	storeFile string     `json:"-"`
}

type StoredAccount struct{}

// NewStore restores a store from the file located in the datadir
func NewStore(dataDir string) (*FileStore, error) {
	return restore(filepath.Join(dataDir, storeFileName))
}

// restore the state of the store from the file.
// Creates a new empty store file if doesn't exist
func restore(file string) (*FileStore, error) {
	if _, err := os.Stat(file); os.IsNotExist(err) {
		// create a new FileStore if previously didn't exist (e.g. first run)
		s := &FileStore{
			Accounts:                make(map[string]*Account),
			mux:                     sync.Mutex{},
			SetupKeyID2AccountID:    make(map[string]string),
			PeerKeyID2AccountID:     make(map[string]string),
			UserID2AccountID:        make(map[string]string),
			PrivateDomain2AccountID: make(map[string]string),
			storeFile:               file,
		}

		err = s.persist(file)
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

	for accountID, account := range store.Accounts {
		for setupKeyId := range account.SetupKeys {
			store.SetupKeyID2AccountID[strings.ToUpper(setupKeyId)] = accountID
		}

		for _, peer := range account.Peers {
			store.PeerKeyID2AccountID[peer.Key] = accountID
		}
		for _, user := range account.Users {
			store.UserID2AccountID[user.Id] = accountID
		}
		for _, user := range account.Users {
			store.UserID2AccountID[user.Id] = accountID
		}

		if account.Domain != "" && account.DomainCategory == PrivateCategory &&
			account.IsDomainPrimaryAccount {
			store.PrivateDomain2AccountID[account.Domain] = accountID
		}
	}

	return store, nil
}

// persist account data to a file
// It is recommended to call it with locking FileStore.mux
func (s *FileStore) persist(file string) error {
	return util.WriteJson(file, s)
}

// SaveAccount updates an existing account or adds a new one
func (s *FileStore) SaveAccount(account *Account) error {
	s.mux.Lock()
	defer s.mux.Unlock()

	accountCopy := account.Copy()

	// todo will override, handle existing keys
	s.Accounts[accountCopy.Id] = accountCopy

	// todo check that account.Id and keyId are not exist already
	// because if keyId exists for other accounts this can be bad
	for keyId := range accountCopy.SetupKeys {
		s.SetupKeyID2AccountID[strings.ToUpper(keyId)] = accountCopy.Id
	}

	// enforce peer to account index and delete peer to route indexes for rebuild
	for _, peer := range accountCopy.Peers {
		s.PeerKeyID2AccountID[peer.Key] = accountCopy.Id
	}

	for _, user := range accountCopy.Users {
		s.UserID2AccountID[user.Id] = accountCopy.Id
	}

	if accountCopy.DomainCategory == PrivateCategory && accountCopy.IsDomainPrimaryAccount {
		s.PrivateDomain2AccountID[accountCopy.Domain] = accountCopy.Id
	}

	return s.persist(s.storeFile)
}

// GetAccountByPrivateDomain returns account by private domain
func (s *FileStore) GetAccountByPrivateDomain(domain string) (*Account, error) {
	accountID, accountIDFound := s.PrivateDomain2AccountID[strings.ToLower(domain)]
	if !accountIDFound {
		return nil, status.Errorf(
			codes.NotFound,
			"provided domain is not registered or is not private",
		)
	}

	account, err := s.GetAccount(accountID)
	if err != nil {
		return nil, err
	}

	return account.Copy(), nil
}

// GetAccountBySetupKey returns account by setup key id
func (s *FileStore) GetAccountBySetupKey(setupKey string) (*Account, error) {
	accountID, accountIDFound := s.SetupKeyID2AccountID[strings.ToUpper(setupKey)]
	if !accountIDFound {
		return nil, status.Errorf(codes.NotFound, "provided setup key doesn't exists")
	}

	account, err := s.GetAccount(accountID)
	if err != nil {
		return nil, err
	}

	return account.Copy(), nil
}

// GetAllAccounts returns all accounts
func (s *FileStore) GetAllAccounts() (all []*Account) {
	s.mux.Lock()
	defer s.mux.Unlock()
	for _, a := range s.Accounts {
		all = append(all, a.Copy())
	}

	return all
}

// GetAccount returns an account for id
func (s *FileStore) GetAccount(accountID string) (*Account, error) {
	account, accountFound := s.Accounts[accountID]
	if !accountFound {
		return nil, status.Errorf(codes.NotFound, "account not found")
	}

	return account.Copy(), nil
}

// GetAccountByUser returns a user account
func (s *FileStore) GetAccountByUser(userID string) (*Account, error) {
	s.mux.Lock()
	defer s.mux.Unlock()

	accountID, accountIDFound := s.UserID2AccountID[userID]
	if !accountIDFound {
		return nil, status.Errorf(codes.NotFound, "account not found")
	}

	return s.GetAccount(accountID)
}

// GetAccountByPeerPubKey returns an account for a given peer WireGuard public key
func (s *FileStore) GetAccountByPeerPubKey(peerKey string) (*Account, error) {
	s.mux.Lock()
	defer s.mux.Unlock()

	accountID, accountIDFound := s.PeerKeyID2AccountID[peerKey]
	if !accountIDFound {
		return nil, status.Errorf(codes.NotFound, "Provided peer key doesn't exists %s", peerKey)
	}

	return s.GetAccount(accountID)
}

// GetInstallationID returns the installation ID from the store
func (s *FileStore) GetInstallationID() string {
	return s.InstallationID
}

// SaveInstallationID saves the installation ID
func (s *FileStore) SaveInstallationID(id string) error {
	s.mux.Lock()
	defer s.mux.Unlock()

	s.InstallationID = id

	return s.persist(s.storeFile)
}
