package peer

import (
	log "github.com/sirupsen/logrus"
	"github.com/wiretrustee/wiretrustee/signal/proto"
)

// Peer representation of a connected Peer
type Peer struct {
	// a unique id of the Peer (e.g. sha256 fingerprint of the Wireguard public key)
	Id string

	//a gRpc connection stream to the Peer
	Stream proto.SignalExchange_ConnectStreamServer
}

// NewPeer creates a new instance of a connected Peer
func NewPeer(id string, stream proto.SignalExchange_ConnectStreamServer) *Peer {
	return &Peer{
		Id:     id,
		Stream: stream,
	}
}

// Registry registry that holds all currently connected Peers
type Registry struct {
	// Peer.key -> Peer
	Peers map[string]*Peer
}

// NewRegistry creates a new connected Peer registry
func NewRegistry() *Registry {
	return &Registry{
		Peers: make(map[string]*Peer),
	}
}

// Register registers peer in the registry
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

// DeregisterHub deregister Peer from the Registry (usually once it disconnects)
func (reg *Registry) DeregisterHub(peer *Peer) {
	if _, ok := reg.Peers[peer.Id]; ok {
		delete(reg.Peers, peer.Id)
		log.Printf("deregistered peer [%s]", peer.Id)
	}
}
