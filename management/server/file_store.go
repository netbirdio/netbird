package server

import (
	"fmt"
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
	SetupKeyId2AccountId    map[string]string              `json:"-"`
	PeerKeyId2AccountId     map[string]string              `json:"-"`
	UserId2AccountId        map[string]string              `json:"-"`
	PrivateDomain2AccountId map[string]string              `json:"-"`
	PeerKeyId2SrcRulesId    map[string]map[string]struct{} `json:"-"`
	PeerKeyId2DstRulesId    map[string]map[string]struct{} `json:"-"`

	// mutex to synchronise Store read/write operations
	mux       sync.Mutex `json:"-"`
	storeFile string     `json:"-"`
}

type StoredAccount struct{}

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
			Accounts:                make(map[string]*Account),
			mux:                     sync.Mutex{},
			SetupKeyId2AccountId:    make(map[string]string),
			PeerKeyId2AccountId:     make(map[string]string),
			UserId2AccountId:        make(map[string]string),
			PrivateDomain2AccountId: make(map[string]string),
			PeerKeyId2SrcRulesId:    make(map[string]map[string]struct{}),
			PeerKeyId2DstRulesId:    make(map[string]map[string]struct{}),
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
	store.SetupKeyId2AccountId = make(map[string]string)
	store.PeerKeyId2AccountId = make(map[string]string)
	store.UserId2AccountId = make(map[string]string)
	store.PrivateDomain2AccountId = make(map[string]string)
	store.PeerKeyId2SrcRulesId = map[string]map[string]struct{}{}
	store.PeerKeyId2DstRulesId = map[string]map[string]struct{}{}

	for accountId, account := range store.Accounts {
		for setupKeyId := range account.SetupKeys {
			store.SetupKeyId2AccountId[strings.ToUpper(setupKeyId)] = accountId
		}
		for _, rule := range account.Rules {
			for _, groupID := range rule.Source {
				if group, ok := account.Groups[groupID]; ok {
					for _, peerID := range group.Peers {
						rules := store.PeerKeyId2SrcRulesId[peerID]
						if rules == nil {
							rules = map[string]struct{}{}
							store.PeerKeyId2SrcRulesId[peerID] = rules
						}
						rules[rule.ID] = struct{}{}
					}
				}
			}
			for _, groupID := range rule.Destination {
				if group, ok := account.Groups[groupID]; ok {
					for _, peerID := range group.Peers {
						rules := store.PeerKeyId2DstRulesId[peerID]
						if rules == nil {
							rules = map[string]struct{}{}
							store.PeerKeyId2DstRulesId[peerID] = rules
						}
						rules[rule.ID] = struct{}{}
					}
				}
			}
		}
		for _, peer := range account.Peers {
			store.PeerKeyId2AccountId[peer.Key] = accountId
		}
		for _, user := range account.Users {
			store.UserId2AccountId[user.Id] = accountId
		}
		for _, user := range account.Users {
			store.UserId2AccountId[user.Id] = accountId
		}
		if account.Domain != "" && account.DomainCategory == PrivateCategory &&
			account.IsDomainPrimaryAccount {
			store.PrivateDomain2AccountId[account.Domain] = accountId
		}
	}

	return store, nil
}

// persist persists account data to a file
// It is recommended to call it with locking FileStore.mux
func (s *FileStore) persist(file string) error {
	return util.WriteJson(file, s)
}

// SavePeer saves updated peer
func (s *FileStore) SavePeer(accountId string, peer *Peer) error {
	s.mux.Lock()
	defer s.mux.Unlock()

	account, err := s.GetAccount(accountId)
	if err != nil {
		return err
	}

	// if it is new peer, add it to default 'All' group
	allGroup, err := account.GetGroupAll()
	if err != nil {
		return err
	}

	ind := -1
	for i, pid := range allGroup.Peers {
		if pid == peer.Key {
			ind = i
			break
		}
	}

	if ind < 0 {
		allGroup.Peers = append(allGroup.Peers, peer.Key)
	}

	account.Peers[peer.Key] = peer
	return s.persist(s.storeFile)
}

// DeletePeer deletes peer from the Store
func (s *FileStore) DeletePeer(accountId string, peerKey string) (*Peer, error) {
	s.mux.Lock()
	defer s.mux.Unlock()

	account, err := s.GetAccount(accountId)
	if err != nil {
		return nil, err
	}

	peer := account.Peers[peerKey]
	if peer == nil {
		return nil, status.Errorf(codes.NotFound, "peer not found")
	}

	delete(account.Peers, peerKey)
	delete(s.PeerKeyId2AccountId, peerKey)
	delete(s.PeerKeyId2DstRulesId, peerKey)
	delete(s.PeerKeyId2SrcRulesId, peerKey)

	// cleanup groups
	var peers []string
	for _, g := range account.Groups {
		for _, p := range g.Peers {
			if p != peerKey {
				peers = append(peers, p)
			}
		}
		g.Peers = peers
	}

	err = s.persist(s.storeFile)
	if err != nil {
		return nil, err
	}

	return peer, nil
}

// GetPeer returns a peer from a Store
func (s *FileStore) GetPeer(peerKey string) (*Peer, error) {
	s.mux.Lock()
	defer s.mux.Unlock()

	accountId, accountIdFound := s.PeerKeyId2AccountId[peerKey]
	if !accountIdFound {
		return nil, status.Errorf(codes.NotFound, "peer not found")
	}

	account, err := s.GetAccount(accountId)
	if err != nil {
		return nil, err
	}

	if peer, ok := account.Peers[peerKey]; ok {
		return peer, nil
	}

	return nil, status.Errorf(codes.NotFound, "peer not found")
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
		s.SetupKeyId2AccountId[strings.ToUpper(keyId)] = account.Id
	}

	for _, peer := range account.Peers {
		s.PeerKeyId2AccountId[peer.Key] = account.Id
	}

	// remove all peers related to account from rules indexes
	cleanIDs := make([]string, 0)
	for key := range s.PeerKeyId2SrcRulesId {
		if accountID, ok := s.PeerKeyId2AccountId[key]; ok && accountID == account.Id {
			cleanIDs = append(cleanIDs, key)
		}
	}
	for _, key := range cleanIDs {
		delete(s.PeerKeyId2SrcRulesId, key)
	}
	cleanIDs = cleanIDs[:0]
	for key := range s.PeerKeyId2DstRulesId {
		if accountID, ok := s.PeerKeyId2AccountId[key]; ok && accountID == account.Id {
			cleanIDs = append(cleanIDs, key)
		}
	}
	for _, key := range cleanIDs {
		delete(s.PeerKeyId2DstRulesId, key)
	}

	// rebuild rule indexes
	for _, rule := range account.Rules {
		for _, gid := range rule.Source {
			g, ok := account.Groups[gid]
			if !ok {
				break
			}
			for _, pid := range g.Peers {
				rules := s.PeerKeyId2SrcRulesId[pid]
				if rules == nil {
					rules = map[string]struct{}{}
					s.PeerKeyId2SrcRulesId[pid] = rules
				}
				rules[rule.ID] = struct{}{}
			}
		}
		for _, gid := range rule.Destination {
			g, ok := account.Groups[gid]
			if !ok {
				break
			}
			for _, pid := range g.Peers {
				rules := s.PeerKeyId2DstRulesId[pid]
				if rules == nil {
					rules = map[string]struct{}{}
					s.PeerKeyId2DstRulesId[pid] = rules
				}
				rules[rule.ID] = struct{}{}
			}
		}
	}

	for _, user := range account.Users {
		s.UserId2AccountId[user.Id] = account.Id
	}

	if account.DomainCategory == PrivateCategory && account.IsDomainPrimaryAccount {
		s.PrivateDomain2AccountId[account.Domain] = account.Id
	}

	return s.persist(s.storeFile)
}

func (s *FileStore) GetAccountByPrivateDomain(domain string) (*Account, error) {
	accountId, accountIdFound := s.PrivateDomain2AccountId[strings.ToLower(domain)]
	if !accountIdFound {
		return nil, status.Errorf(
			codes.NotFound,
			"provided domain is not registered or is not private",
		)
	}

	account, err := s.GetAccount(accountId)
	if err != nil {
		return nil, err
	}

	return account, nil
}

func (s *FileStore) GetAccountBySetupKey(setupKey string) (*Account, error) {
	accountId, accountIdFound := s.SetupKeyId2AccountId[strings.ToUpper(setupKey)]
	if !accountIdFound {
		return nil, status.Errorf(codes.NotFound, "provided setup key doesn't exists")
	}

	account, err := s.GetAccount(accountId)
	if err != nil {
		return nil, err
	}

	return account, nil
}

func (s *FileStore) GetAccountPeers(accountId string) ([]*Peer, error) {
	s.mux.Lock()
	defer s.mux.Unlock()

	account, err := s.GetAccount(accountId)
	if err != nil {
		return nil, err
	}

	var peers []*Peer
	for _, peer := range account.Peers {
		peers = append(peers, peer)
	}

	return peers, nil
}

func (s *FileStore) GetAllAccounts() (all []*Account) {
	for _, a := range s.Accounts {
		all = append(all, a)
	}

	return all
}

func (s *FileStore) GetAccount(accountId string) (*Account, error) {
	account, accountFound := s.Accounts[accountId]
	if !accountFound {
		return nil, status.Errorf(codes.NotFound, "account not found")
	}

	return account, nil
}

func (s *FileStore) GetUserAccount(userId string) (*Account, error) {
	s.mux.Lock()
	defer s.mux.Unlock()

	accountId, accountIdFound := s.UserId2AccountId[userId]
	if !accountIdFound {
		return nil, status.Errorf(codes.NotFound, "account not found")
	}

	return s.GetAccount(accountId)
}

func (s *FileStore) GetPeerAccount(peerKey string) (*Account, error) {
	s.mux.Lock()
	defer s.mux.Unlock()

	accountId, accountIdFound := s.PeerKeyId2AccountId[peerKey]
	if !accountIdFound {
		return nil, status.Errorf(codes.NotFound, "Provided peer key doesn't exists %s", peerKey)
	}

	return s.GetAccount(accountId)
}

func (s *FileStore) GetPeerSrcRules(accountId, peerKey string) ([]*Rule, error) {
	s.mux.Lock()
	defer s.mux.Unlock()

	account, err := s.GetAccount(accountId)
	if err != nil {
		return nil, err
	}

	ruleIDs, ok := s.PeerKeyId2SrcRulesId[peerKey]
	if !ok {
		return nil, fmt.Errorf("no rules for peer: %v", ruleIDs)
	}

	rules := []*Rule{}
	for id := range ruleIDs {
		rule, ok := account.Rules[id]
		if ok {
			rules = append(rules, rule)
		}
	}

	return rules, nil
}

func (s *FileStore) GetPeerDstRules(accountId, peerKey string) ([]*Rule, error) {
	s.mux.Lock()
	defer s.mux.Unlock()

	account, err := s.GetAccount(accountId)
	if err != nil {
		return nil, err
	}

	ruleIDs, ok := s.PeerKeyId2DstRulesId[peerKey]
	if !ok {
		return nil, fmt.Errorf("no rules for peer: %v", ruleIDs)
	}

	rules := []*Rule{}
	for id := range ruleIDs {
		rule, ok := account.Rules[id]
		if ok {
			rules = append(rules, rule)
		}
	}

	return rules, nil
}
