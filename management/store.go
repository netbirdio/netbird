package management

import "sync"

// User represents a user of the system
type User struct {
	Id        string
	SetupKeys map[string]*SetupKey
	Peers     map[string]*Peer
}

// SetupKey represents a pre-authorized key used to register machines (peers)
// One key might have multiple machines
type SetupKey struct {
	key string
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
	mux sync.Mutex
}

func NewStore() *Store {
	return restore("")
}

// restore restores the state of the store from the file
func restore(file string) *Store {
	//todo restore from the file
	return &Store{
		Users: make(map[string]*User),
		mux:   sync.Mutex{},
	}
}

// persist persists user data to a file
// It is recommended to call it with locking Store,mux
func (s *Store) persist() {

}

// AddPeer adds peer to the store and associates it with a User and a SetupKey. Returns related User
// Each User has a list of pre-authorised SetupKey and if no User has a given key nil will be returned, meaning the key is invalid
func (s *Store) AddPeer(setupKey string, peerKey string) *User {
	s.mux.Lock()
	defer s.mux.Unlock()

	for _, u := range s.Users {
		for _, key := range u.SetupKeys {
			if key.key == setupKey {
				u.Peers[peerKey] = &Peer{Key: peerKey, SetupKey: key}
				return u
			}
		}
	}

	s.persist()

	return nil
}

// AddUser adds new user to the store.
func (s *Store) AddUser(user *User) {
	s.mux.Lock()
	defer s.mux.Unlock()
	// todo will override, handle existing keys
	s.Users[user.Id] = user
	s.persist()
}
