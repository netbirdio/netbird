package server

import (
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"net"
	"strings"
	"sync"
)

type AccountManager struct {
	Store Store
	// mutex to synchronise account operations (e.g. generating Peer IP address inside the Network)
	mux sync.Mutex
}

// Account represents a unique account of the system
type Account struct {
	Id        string
	SetupKeys map[string]*SetupKey
	Network   *Network
	Peers     map[string]*Peer
}

// Peer represents a machine connected to the network.
// The Peer is a Wireguard peer identified by a public key
type Peer struct {
	// Wireguard public key
	Key string
	// A setup key this peer was registered with
	SetupKey string
	// IP address of the Peer
	IP net.IP
}

// NewManager creates a new AccountManager with a provided Store
func NewManager(store Store) *AccountManager {
	return &AccountManager{
		Store: store,
		mux:   sync.Mutex{},
	}
}

// GetPeer returns a peer from a Store
func (manager *AccountManager) GetPeer(peerKey string) (*Peer, error) {
	manager.mux.Lock()
	defer manager.mux.Unlock()

	peer, err := manager.Store.GetPeer(peerKey)
	if err != nil {
		return nil, err
	}

	return peer, nil
}

// GetPeersForAPeer returns a list of peers available for a given peer (key)
// Effectively all the peers of the original peer's account except for the peer itself
func (manager *AccountManager) GetPeersForAPeer(peerKey string) ([]*Peer, error) {
	manager.mux.Lock()
	defer manager.mux.Unlock()

	account, err := manager.Store.GetPeerAccount(peerKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Invalid peer key %s", peerKey)
	}

	var res []*Peer
	for _, peer := range account.Peers {
		if peer.Key != peerKey {
			res = append(res, peer)
		}
	}

	return res, nil
}

//GetAccount returns an existing account or error (NotFound) if doesn't exist
func (manager *AccountManager) GetAccount(accountId string) (*Account, error) {
	manager.mux.Lock()
	defer manager.mux.Unlock()

	account, err := manager.Store.GetAccount(accountId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed retrieving account")
	}

	return account, nil
}

// GetOrCreateAccount returns an existing account or creates a new one if doesn't exist
func (manager *AccountManager) GetOrCreateAccount(accountId string) (*Account, error) {
	manager.mux.Lock()
	defer manager.mux.Unlock()

	_, err := manager.Store.GetAccount(accountId)
	if err != nil {
		if s, ok := status.FromError(err); ok && s.Code() == codes.NotFound {
			return manager.createAccount(accountId)
		} else {
			// other error
			return nil, err
		}
	}

	account, err := manager.Store.GetAccount(accountId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed retrieving account")
	}

	return account, nil
}

//AccountExists checks whether account exists (returns true) or not (returns false)
func (manager *AccountManager) AccountExists(accountId string) (*bool, error) {
	manager.mux.Lock()
	defer manager.mux.Unlock()

	var res bool
	_, err := manager.Store.GetAccount(accountId)
	if err != nil {
		if s, ok := status.FromError(err); ok && s.Code() == codes.NotFound {
			res = false
			return &res, nil
		} else {
			return nil, err
		}
	}

	res = true
	return &res, nil
}

// AddAccount generates a new Account with a provided accountId and saves to the Store
func (manager *AccountManager) AddAccount(accountId string) (*Account, error) {

	manager.mux.Lock()
	defer manager.mux.Unlock()

	return manager.createAccount(accountId)

}

func (manager *AccountManager) createAccount(accountId string) (*Account, error) {
	account, _ := newAccountWithId(accountId)

	err := manager.Store.SaveAccount(account)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed creating account")
	}

	return account, nil
}

// AddPeer adds a new peer to the Store.
// Each Account has a list of pre-authorised SetupKey and if no Account has a given key err wit ha code codes.Unauthenticated
// will be returned, meaning the key is invalid
// Each new Peer will be assigned a new next net.IP from the Account.Network and Account.Network.LastIP will be updated (IP's are not reused).
// If the specified setupKey is empty then a new Account will be created //todo remove this part
func (manager *AccountManager) AddPeer(setupKey string, peerKey string) (*Peer, error) {
	manager.mux.Lock()
	defer manager.mux.Unlock()

	upperKey := strings.ToUpper(setupKey)

	var account *Account
	var err error
	var sk *SetupKey
	if len(upperKey) == 0 {
		// Empty setup key, create a new account for it.
		account, sk = newAccount()
	} else {
		account, err = manager.Store.GetAccountBySetupKey(upperKey)
		if err != nil {
			return nil, status.Errorf(codes.NotFound, "unknown setupKey %s", upperKey)
		}

		for _, key := range account.SetupKeys {
			if upperKey == key.Key {
				sk = key
				break
			}
		}

		if sk == nil {
			// shouldn't happen actually
			return nil, status.Errorf(codes.NotFound, "unknown setupKey %s", upperKey)
		}
	}

	if !sk.IsValid() {
		return nil, status.Errorf(codes.FailedPrecondition, "setup key was expired or overused %s", upperKey)
	}

	var takenIps []net.IP
	for _, peer := range account.Peers {
		takenIps = append(takenIps, peer.IP)
	}

	network := account.Network
	nextIp, _ := AllocatePeerIP(network.Net, takenIps)

	newPeer := &Peer{
		Key:      peerKey,
		SetupKey: sk.Key,
		IP:       nextIp,
	}

	account.Peers[newPeer.Key] = newPeer
	err = manager.Store.SaveAccount(account)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed adding peer")
	}

	return newPeer, nil

}

// newAccountWithId creates a new Account with a default SetupKey (doesn't store in a Store) and provided id
func newAccountWithId(accountId string) (*Account, *SetupKey) {

	log.Debugf("creating new account")

	setupKeys := make(map[string]*SetupKey)
	setupKey := GenerateDefaultSetupKey()
	setupKeys[setupKey.Key] = setupKey
	network := &Network{
		Id:  uuid.New().String(),
		Net: net.IPNet{IP: net.ParseIP("100.64.0.0"), Mask: net.IPMask{255, 192, 0, 0}},
		Dns: ""}
	peers := make(map[string]*Peer)

	log.Debugf("created new account %s with setup key %s", accountId, setupKey.Key)

	return &Account{Id: accountId, SetupKeys: setupKeys, Network: network, Peers: peers}, setupKey
}

// newAccount creates a new Account with a default SetupKey (doesn't store in a Store)
func newAccount() (*Account, *SetupKey) {
	accountId := uuid.New().String()
	return newAccountWithId(accountId)
}
