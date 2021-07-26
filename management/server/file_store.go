package server

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/wiretrustee/wiretrustee/util"
)

// storeFileName Store file name. Stored in the datadir
const storeFileName = "store.json"

// FileStore represents an account storage backed by a file persisted to disk
type FileStore struct {
	Accounts             map[string]*Account
	Peers                map[string]*Peer
	SetupKeyId2AccountId map[string]string `json:"-"`
	PeerKeyId2AccountId  map[string]string `json:"-"`

	// mutex to synchronise Store read/write operations
	mux       sync.Mutex `json:"-"`
	storeFile string     `json:"-"`
}

type StoredAccount struct {
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

	store := read.(*FileStore)
	store.storeFile = file
	store.SetupKeyId2AccountId = make(map[string]string)
	for accountId, account := range store.Accounts {
		for setupKeyId := range account.SetupKeys {
			store.SetupKeyId2AccountId[strings.ToLower(setupKeyId)] = accountId
		}
	}
	store.PeerKeyId2AccountId = make(map[string]string)
	for peerId, peer := range store.Peers {
		store.PeerKeyId2AccountId[strings.ToLower(peerId)] = peer.AccountId
	}

	return store, nil
}

// persist persists account data to a file
// It is recommended to call it with locking FileStore.mux
func (s *FileStore) persist(file string) error {
	return util.WriteJson(file, s)
}

// GetPeer returns a peer from a Store
func (s *FileStore) GetPeer(peerKey string) (*Peer, error) {
	s.mux.Lock()
	defer s.mux.Unlock()

	_, accountIdFound := s.PeerKeyId2AccountId[peerKey]
	if !accountIdFound {
		return nil, status.Errorf(codes.Internal, "account not found")
	}
	return s.Peers[peerKey], nil
}

// SavePeer adds peer to the store and associates it with a Account and a SetupKey.
// Each Account has a list of pre-authorised SetupKey and if no Account has a given key err will be returned, meaning the key is invalid
func (s *FileStore) SavePeer(peer *Peer) error {
	s.mux.Lock()
	defer s.mux.Unlock()

	account, accountFound := s.Accounts[peer.AccountId]
	if !accountFound {
		return status.Errorf(codes.Internal, "account not found")
	}

	s.Peers[peer.Key] = peer
	s.PeerKeyId2AccountId[peer.Key] = account.Id
	err := s.persist(s.storeFile)
	if err != nil {
		return err
	}
	return nil
}

// SaveAccount updates an existing account or adds a new one
func (s *FileStore) SaveAccount(account *Account) error {
	s.mux.Lock()
	defer s.mux.Unlock()

	// todo will override, handle existing keys
	s.Accounts[account.Id] = account

	// todo check that account.Id and keyId are not exist already
	// because if keyId exists for other accounts this can be bad
	for keyId := range account.SetupKeys {
		s.SetupKeyId2AccountId[strings.ToLower(keyId)] = account.Id
	}

	err := s.persist(s.storeFile)
	if err != nil {
		return err
	}

	return nil
}

// GetAccountPeers returns a list of peers available for a given account
// Effectively all the peers of the original peer's account if any
func (s *FileStore) GetAccountPeers(accountId string) ([]*Peer, error) {
	s.mux.Lock()
	defer s.mux.Unlock()

	_, accountFound := s.Accounts[accountId]
	if !accountFound {
		return nil, status.Errorf(codes.Internal, "account not found")
	}
	var peers []*Peer
	for _, peer := range s.Peers {
		if peer.AccountId == accountId {
			peers = append(peers, peer)
		}
	}

	return peers, nil
}

func (s *FileStore) GetAccountBySetupKey(setupKey string) (*Account, error) {

	accountId, accountIdFound := s.SetupKeyId2AccountId[strings.ToLower(setupKey)]
	if !accountIdFound {
		return nil, status.Errorf(codes.NotFound, "provided setup key doesn't exists")
	}

	account, err := s.GetAccount(accountId)
	if err != nil {
		return nil, err
	}

	return account, nil
}

func (s *FileStore) GetAccount(accountId string) (*Account, error) {

	account, accountFound := s.Accounts[accountId]
	if !accountFound {
		return nil, status.Errorf(codes.Internal, "account not found")
	}

	return account, nil
}

func (s *FileStore) GetPeerAccount(peerKey string) (*Account, error) {
	s.mux.Lock()
	defer s.mux.Unlock()

	accountId, accountIdFound := s.PeerKeyId2AccountId[peerKey]
	if !accountIdFound {
		return nil, status.Errorf(codes.NotFound, "Provided peer key doesn't exists %s", peerKey)
	}

	account, accountFound := s.Accounts[accountId]
	if !accountFound {
		return nil, status.Errorf(codes.Internal, "account not found")
	}

	return account, nil
}
