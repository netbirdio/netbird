package server

type Store interface {
	GetPeer(peerId string) (*Peer, error)
	DeletePeer(accountId string, peerKey string) (*Peer, error)
	GetAccount(accountId string) (*Account, error)
	GetPeerAccount(peerId string) (*Account, error)
	GetAccountBySetupKey(setupKey string) (*Account, error)
	SaveAccount(account *Account) error
}
