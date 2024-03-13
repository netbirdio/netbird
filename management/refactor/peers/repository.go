package peers

type repository interface {
	FindPeerByPubKey(pubKey string) (*Peer, error)
	FindPeerByID(id string) (*Peer, error)
	FindAllPeersInAccount(id string) ([]*Peer, error)
	UpdatePeer(peer Peer) error
}
