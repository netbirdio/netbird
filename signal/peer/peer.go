package peer

import (
	"github.com/netbirdio/netbird/signal/proto"
	log "github.com/sirupsen/logrus"
	"sync"
	"time"
)

// Peer representation of a connected Peer
type Peer struct {
	// a unique id of the Peer (e.g. sha256 fingerprint of the Wireguard public key)
	Id string

	StreamID int64

	//a gRpc connection stream to the Peer
	Stream proto.SignalExchange_ConnectStreamServer
}

// NewPeer creates a new instance of a connected Peer
func NewPeer(id string, stream proto.SignalExchange_ConnectStreamServer) *Peer {
	return &Peer{
		Id:       id,
		Stream:   stream,
		StreamID: time.Now().UnixNano(),
	}
}

// Registry that holds all currently connected Peers
type Registry struct {
	// Peer.key -> Peer
	Peers sync.Map
	// regMutex ensures that registration and de-registrations are safe
	regMutex sync.Mutex
}

// NewRegistry creates a new connected Peer registry
func NewRegistry() *Registry {
	return &Registry{
		regMutex: sync.Mutex{},
	}
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
	registry.regMutex.Lock()
	defer registry.regMutex.Unlock()

	// can be that peer already exists, but it is fine (e.g. reconnect)
	p, loaded := registry.Peers.LoadOrStore(peer.Id, peer)
	if loaded {
		pp := p.(*Peer)
		log.Warnf("peer [%s] is already registered [new streamID %d, previous StreamID %d]. Will override stream.",
			peer.Id, peer.StreamID, pp.StreamID)
		registry.Peers.Store(peer.Id, peer)
	}
	log.Debugf("peer registered [%s]", peer.Id)
}

// Deregister Peer from the Registry (usually once it disconnects)
func (registry *Registry) Deregister(peer *Peer) {
	registry.regMutex.Lock()
	defer registry.regMutex.Unlock()

	p, loaded := registry.Peers.LoadAndDelete(peer.Id)
	if loaded {
		pp := p.(*Peer)
		if peer.StreamID < pp.StreamID {
			registry.Peers.Store(peer.Id, p)
			log.Warnf("attempted to remove newer registered stream of a peer [%s] [newer streamID %d, previous StreamID %d]. Ignoring.",
				peer.Id, pp.StreamID, peer.StreamID)
			return
		}
	}
	log.Debugf("peer deregistered [%s]", peer.Id)
}
