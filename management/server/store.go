package server

import (
	"github.com/netbirdio/netbird/route"
	"net/netip"
)

type Store interface {
	GetPeer(peerKey string) (*Peer, error)
	DeletePeer(accountId string, peerKey string) (*Peer, error)
	SavePeer(accountId string, peer *Peer) error
	GetAllAccounts() []*Account
	GetAccount(accountId string) (*Account, error)
	GetUserAccount(userId string) (*Account, error)
	GetAccountPeers(accountId string) ([]*Peer, error)
	GetPeerAccount(peerKey string) (*Account, error)
	GetPeerSrcRules(accountId, peerKey string) ([]*Rule, error)
	GetPeerDstRules(accountId, peerKey string) ([]*Rule, error)
	GetAccountBySetupKey(setupKey string) (*Account, error)
	GetAccountByPrivateDomain(domain string) (*Account, error)
	SaveAccount(account *Account) error
	GetPeerRoutes(peerKey string) ([]*route.Route, error)
	GetRoutesByPrefix(accountID string, prefix netip.Prefix) ([]*route.Route, error)
}
