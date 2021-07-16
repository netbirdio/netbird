package management

import (
	"fmt"
	"github.com/wiretrustee/wiretrustee/util"
	"path/filepath"
	"strings"
	"sync"
)

const storeFileName = "store.json"

// Account represents a unique account of the system
type Account struct {
	Id        string
	SetupKeys map[string]*SetupKey
	Peers     map[string]*Peer
}

// SetupKey represents a pre-authorized key used to register machines (peers)
// One key might have multiple machines
type SetupKey struct {
	Key string
}

// Peer represents a machine connected to the network.
// The Peer is a Wireguard peer identified by a public key
type Peer struct {
	Key string
	// A setup key this peer was registered with
	SetupKey *SetupKey
}

// Store represents an account storage
type Store struct {
	Accounts map[string]*Account

	// mutex to synchronise Store read/write operations
	mux       sync.Mutex `json:"-"`
	storeFile string     `json:"-"`
}

func NewStore(dataDir string) (*Store, error) {
	return restore(filepath.Join(dataDir, storeFileName))
}

// restore restores the state of the store from the file
func restore(file string) (*Store, error) {

	read, err := util.ReadJson(file, &Store{})
	if err != nil {
		return nil, err
	}
	read.(*Store).storeFile = file

	return read.(*Store), nil
}

// persist persists account data to a file
// It is recommended to call it with locking Store,mux
func (s *Store) persist(file string) error {
	return util.WriteJson(file, s)
}

// AddPeer adds peer to the store and associates it with a Account and a SetupKey. Returns related Account
// Each Account has a list of pre-authorised SetupKey and if no Account has a given key nil will be returned, meaning the key is invalid
func (s *Store) AddPeer(setupKey string, peerKey string) error {
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
func (s *Store) AddAccount(account *Account) error {
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
