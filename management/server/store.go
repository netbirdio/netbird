package server

type Store interface {
	GetPeer(peerKey string) (*Peer, error)
	DeletePeer(accountId string, peerKey string) (*Peer, error)
	SavePeer(accountId string, peer *Peer) error
	GetAccount(accountId string) (*Account, error)
	GetPeerAccount(peerKey string) (*Account, error)
	GetAccountBySetupKey(setupKey string) (*Account, error)
	SaveAccount(account *Account) error
}
