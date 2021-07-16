package management

import (
	"fmt"
	"github.com/wiretrustee/wiretrustee/util"
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

	read, err := util.ReadJson(file, &Store{})
	if err != nil {
		return nil, err
	}
	read.(*Store).config = file

	return read.(*Store), nil
}

// persist persists user data to a file
// It is recommended to call it with locking Store,mux
func (s *Store) persist(file string) error {
	return util.WriteJson(file, s)
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
