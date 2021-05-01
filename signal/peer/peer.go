package peer

import (
	log "github.com/sirupsen/logrus"
	"github.com/wiretrustee/wiretrustee/signal/proto"
)

// Representation of a connected Peer
type Peer struct {
	// a unique id of the Peer (e.g. sha256 fingerprint of the Wireguard public key)
	Id string

	//a gRpc connection stream to the Peer
	Stream proto.SignalExchange_ConnectStreamServer
}

func NewPeer(id string, stream proto.SignalExchange_ConnectStreamServer) *Peer {
	return &Peer{
		Id:     id,
		Stream: stream,
	}
}

// registry that holds all currently connected Peers
type Registry struct {
	// Peer.key -> Peer
	Peers map[string]*Peer
}

func NewRegistry() *Registry {
	return &Registry{
		Peers: make(map[string]*Peer),
	}
}

// Registers peer in the registry
func (reg *Registry) Register(peer *Peer) {
	if _, exists := reg.Peers[peer.Id]; exists {
		log.Warnf("peer [%s] has been already registered", peer.Id)
	} else {
		log.Printf("registering new peer [%s]", peer.Id)
	}
	//replace Peer even if exists
	//todo should we really replace?
	reg.Peers[peer.Id] = peer
}

// Deregister Peer from the Registry (usually once it disconnects)
func (reg *Registry) DeregisterHub(peer *Peer) {
	if _, ok := reg.Peers[peer.Id]; ok {
		delete(reg.Peers, peer.Id)
		log.Printf("deregistered peer [%s]", peer.Id)
	}
}
