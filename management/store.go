package management

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// User represents a user of the system
type User struct {
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

// Store represents a user storage
type Store struct {
	Users map[string]*User

	// mutex to synchronise Store read/write operations
	mux    sync.Mutex `json:"-"`
	config string     `json:"-"`
}

func NewStore(config string) (*Store, error) {
	return restore(config)
}

// restore restores the state of the store from the file
func restore(file string) (*Store, error) {

	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	bs, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}

	var store Store
	err = json.Unmarshal(bs, &store)
	if err != nil {
		return nil, err
	}

	store.config = file

	return &store, nil
}

// persist persists user data to a file
// It is recommended to call it with locking Store,mux
func (s *Store) persist(file string) error {

	configDir := filepath.Dir(file)
	err := os.MkdirAll(configDir, 0750)
	if err != nil {
		return err
	}

	bs, err := json.MarshalIndent(s, "", "    ")
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(file, bs, 0600)
	if err != nil {
		return err
	}

	return nil
}

// AddPeer adds peer to the store and associates it with a User and a SetupKey. Returns related User
// Each User has a list of pre-authorised SetupKey and if no User has a given key nil will be returned, meaning the key is invalid
func (s *Store) AddPeer(setupKey string, peerKey string) error {
	s.mux.Lock()
	defer s.mux.Unlock()

	for _, u := range s.Users {
		for _, key := range u.SetupKeys {
			if key.Key == strings.ToLower(setupKey) {
				u.Peers[peerKey] = &Peer{Key: peerKey, SetupKey: key}
				err := s.persist(s.config)
				if err != nil {
					return err
				}
				return nil
			}
		}
	}

	return fmt.Errorf("invalid setup key")
}

// AddUser adds new user to the store.
func (s *Store) AddUser(user *User) error {
	s.mux.Lock()
	defer s.mux.Unlock()
	// todo will override, handle existing keys
	s.Users[user.Id] = user
	err := s.persist(s.config)
	if err != nil {
		return err
	}

	return nil
}
