package management

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/wiretrustee/wiretrustee/util"
)

// storeFileName Store file name. Stored in the datadir
const storeFileName = "store.json"

// Store represents an account storage
type FileStore struct {
	Accounts map[string]*Account

	// mutex to synchronise Store read/write operations
	mux       sync.Mutex `json:"-"`
	storeFile string     `json:"-"`
}

// NewStore restores a store from the file located in the datadir
func NewStore(dataDir string) (*FileStore, error) {
	return restore(filepath.Join(dataDir, storeFileName))
}

// restore restores the state of the store from the file.
// Creates a new empty store file if doesn't exist
func restore(file string) (*FileStore, error) {

	if _, err := os.Stat(file); os.IsNotExist(err) {
		// create a new FileStore if previously didn't exist (e.g. first run)
		s := &FileStore{
			Accounts:  make(map[string]*Account),
			mux:       sync.Mutex{},
			storeFile: file,
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
	read.(*FileStore).storeFile = file

	return read.(*FileStore), nil
}

// persist persists account data to a file
// It is recommended to call it with locking FileStore.mux
func (s *FileStore) persist(file string) error {
	return util.WriteJson(file, s)
}

// AddPeer adds peer to the store and associates it with a Account and a SetupKey. Returns related Account
// Each Account has a list of pre-authorised SetupKey and if no Account has a given key nil will be returned, meaning the key is invalid
func (s *FileStore) AddPeer(setupKey string, peerKey string) error {
	s.mux.Lock()
	defer s.mux.Unlock()

	for _, u := range s.Accounts {
		for _, key := range u.SetupKeys {
			if key.Key == strings.ToLower(setupKey) {
				u.Peers[peerKey] = &Peer{Key: peerKey, SetupKey: key}
				err := s.persist(s.storeFile)
				if err != nil {
					return err
				}
				return nil
			}
		}
	}

	return fmt.Errorf("invalid setup key")
}

// AddAccount adds new account to the store.
func (s *FileStore) AddAccount(account *Account) error {
	s.mux.Lock()
	defer s.mux.Unlock()
	// todo will override, handle existing keys
	s.Accounts[account.Id] = account
	err := s.persist(s.storeFile)
	if err != nil {
		return err
	}

	return nil
}
