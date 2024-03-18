package peers

import "github.com/netbirdio/netbird/management/refactor/resources/peers/types"

type Repository interface {
	FindPeerByPubKey(pubKey string) (types.Peer, error)
	FindPeerByID(id string) (types.Peer, error)
	FindAllPeersInAccount(id string) ([]types.Peer, error)
	UpdatePeer(peer types.Peer) error
}
