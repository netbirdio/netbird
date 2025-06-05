package peer

import (
	"context"
	"sync"
	"time"

	"errors"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/signal/metrics"
	"github.com/netbirdio/netbird/signal/proto"
)

var (
	ErrPeerAlreadyRegistered = errors.New("peer already registered")
)

// Peer representation of a connected Peer
type Peer struct {
	// a unique id of the Peer (e.g. sha256 fingerprint of the Wireguard public key)
	Id string

	StreamID int64

	// a gRpc connection stream to the Peer
	Stream proto.SignalExchange_ConnectStreamServer

	// registration time
	RegisteredAt time.Time

	Cancel context.CancelFunc
}

// NewPeer creates a new instance of a connected Peer
func NewPeer(id string, stream proto.SignalExchange_ConnectStreamServer) *Peer {
	return &Peer{
		Id:           id,
		Stream:       stream,
		StreamID:     time.Now().UnixNano(),
		RegisteredAt: time.Now(),
	}
}

// NewPeer creates a new instance of a connected Peer
func NewPeerPool(id string, stream proto.SignalExchange_ConnectStreamServer, cancel context.CancelFunc) *Peer {
	return &Peer{
		Id:           id,
		Stream:       stream,
		StreamID:     time.Now().UnixNano(),
		RegisteredAt: time.Now(),
		Cancel:       cancel,
	}
}

// Registry that holds all currently connected Peers
type Registry struct {
	// Peer.key -> Peer
	Peers sync.Map
	// regMutex ensures that registration and de-registrations are safe
	regMutex sync.Mutex
	metrics  *metrics.AppMetrics
}

// NewRegistry creates a new connected Peer registry
func NewRegistry(metrics *metrics.AppMetrics) *Registry {
	return &Registry{
		regMutex: sync.Mutex{},
		metrics:  metrics,
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
	start := time.Now()

	registry.regMutex.Lock()
	defer registry.regMutex.Unlock()

	// can be that peer already exists, but it is fine (e.g. reconnect)
	p, loaded := registry.Peers.LoadOrStore(peer.Id, peer)
	if loaded {
		pp := p.(*Peer)
		log.Tracef("peer [%s] is already registered [new streamID %d, previous StreamID %d]. Will override stream.",
			peer.Id, peer.StreamID, pp.StreamID)
		registry.Peers.Store(peer.Id, peer)
		return
	}

	log.Debugf("peer registered [%s]", peer.Id)
	registry.metrics.ActivePeers.Add(context.Background(), 1)

	// record time as milliseconds
	registry.metrics.RegistrationDelay.Record(context.Background(), float64(time.Since(start).Nanoseconds())/1e6)

	registry.metrics.Registrations.Add(context.Background(), 1)
}

// Register registers peer in the registry
func (registry *Registry) RegisterPool(peer *Peer) error {
	start := time.Now()

	// can be that peer already exists, but it is fine (e.g. reconnect)
	p, loaded := registry.Peers.LoadOrStore(peer.Id, peer)
	if loaded {
		pp := p.(*Peer)
		if peer.StreamID > pp.StreamID {
			log.Tracef("peer [%s] is already registered [new streamID %d, previous StreamID %d]. Will override stream.",
				peer.Id, peer.StreamID, pp.StreamID)
			if swapped := registry.Peers.CompareAndSwap(peer.Id, pp, peer); !swapped {
				return registry.RegisterPool(peer)
			}
			pp.Cancel()
		}
		return ErrPeerAlreadyRegistered
	}

	log.Debugf("peer registered [%s]", peer.Id)
	registry.metrics.ActivePeers.Add(context.Background(), 1)

	// record time as milliseconds
	registry.metrics.RegistrationDelay.Record(context.Background(), float64(time.Since(start).Nanoseconds())/1e6)

	registry.metrics.Registrations.Add(context.Background(), 1)

	return nil
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
			log.Debugf("attempted to remove newer registered stream of a peer [%s] [newer streamID %d, previous StreamID %d]. Ignoring.",
				peer.Id, pp.StreamID, peer.StreamID)
			return
		}
		registry.metrics.ActivePeers.Add(context.Background(), -1)
		log.Debugf("peer deregistered [%s]", peer.Id)
		registry.metrics.Deregistrations.Add(context.Background(), 1)
	}
}

// Deregister Peer from the Registry (usually once it disconnects)
func (registry *Registry) DeregisterPool(peer *Peer) {
	if deleted := registry.Peers.CompareAndDelete(peer.Id, peer); deleted {
		registry.metrics.ActivePeers.Add(context.Background(), -1)
		log.Debugf("peer deregistered [%s]", peer.Id)
		registry.metrics.Deregistrations.Add(context.Background(), 1)
	}
}
