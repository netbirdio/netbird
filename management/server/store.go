package server

import (
	"github.com/netbirdio/netbird/route"
	"net/netip"
)

type StoreV2 interface {
	GetAllAccounts() []*Account
	GetAccount(accountID string) (*Account, error)
	GetAccountByUser(userID string) (*Account, error)
	GetAccountByPeerPubKey(peerID string) (*Account, error)
	GetAccountBySetupKey(setupKey string) (*Account, error) //todo use key hash later
	GetAccountByPrivateDomain(domain string) (*Account, error)
	SaveAccount(account *Account) error
	GetInstallationID() string
	SaveInstallationID(id string) error
}

type Store interface {
	DeletePeer(accountId string, peerKey string) (*Peer, error) //no need can get from account
	SavePeer(accountId string, peer *Peer) error                //no need can get from account
	GetAllAccounts() []*Account
	GetAccount(accountId string) (*Account, error)
	GetUserAccount(userId string) (*Account, error)
	GetAccountPeers(accountId string) ([]*Peer, error) //no need can get from account
	GetPeerAccount(peerKey string) (*Account, error)
	GetAccountBySetupKey(setupKey string) (*Account, error)
	GetAccountByPrivateDomain(domain string) (*Account, error)
	SaveAccount(account *Account) error
	GetPeerRoutes(peerKey string) ([]*route.Route, error)                            //no need can get from account
	GetRoutesByPrefix(accountID string, prefix netip.Prefix) ([]*route.Route, error) //no need can get from account
	GetInstallationID() string
	SaveInstallationID(id string) error
}
