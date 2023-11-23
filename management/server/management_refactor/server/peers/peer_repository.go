package peers

type PeerRepository interface {
	findPeerByPubKey(pubKey string) (Peer, error)
	updatePeer(peer Peer) error
}
