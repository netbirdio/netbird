package peer

import (
	log "github.com/sirupsen/logrus"
	"github.com/wiretrustee/wiretrustee/signal/proto"
	"sync"
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
	Peers sync.Map
}

// NewRegistry creates a new connected Peer registry
func NewRegistry() *Registry {
	return &Registry{}
}

// Get gets a peer from the registry
func (registry *Registry) Get(peerId string) (*Peer, bool) {
	if load, ok := registry.Peers.Load(peerId); ok {
		return load.(*Peer), ok
	}
	return nil, false

}

func (registry *Registry) IsPeerRegistered(peerId string) bool {
	if _, ok := registry.Peers.Load(peerId); ok {
		return ok
	}
	return false
}

// Register registers peer in the registry
func (registry *Registry) Register(peer *Peer) {
	// can be that peer already exists but it is fine (e.g. reconnect)
	// todo investigate what happens to the old peer (especially Peer.Stream) when we override it
	registry.Peers.Store(peer.Id, peer)
	log.Debugf("peer registered [%s]", peer.Id)

}

// Deregister deregister Peer from the Registry (usually once it disconnects)
func (registry *Registry) Deregister(peer *Peer) {
	_, loaded := registry.Peers.LoadAndDelete(peer.Id)
	if loaded {
		log.Debugf("peer deregistered [%s]", peer.Id)
	} else {
		log.Warnf("attempted to remove non-existent peer [%s]", peer.Id)
	}

}
