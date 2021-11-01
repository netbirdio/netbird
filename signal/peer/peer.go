package peer

import (
	pb "github.com/golang/protobuf/proto"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
	"github.com/wiretrustee/wiretrustee/signal/proto"
	"sync"
)

//Channel abstracts transport that Peer is using to communicate with teh Signal server.
//There are 2 types channels so far: gRPC- and websocket-based.
type Channel interface {
	Send(msg *proto.EncryptedMessage) error
}

type WebsocketChannel struct {
	conn *websocket.Conn
}

func NewWebsocketChannel(conn *websocket.Conn) *WebsocketChannel {
	return &WebsocketChannel{conn: conn}
}

func (c *WebsocketChannel) Send(msg *proto.EncryptedMessage) error {
	b, err := pb.Marshal(msg)
	if err != nil {
		return err
	}
	return c.conn.WriteMessage(websocket.BinaryMessage, b)
}

// Peer representation of a connected Peer
type Peer struct {
	// a unique id of the Peer (e.g. sha256 fingerprint of the Wireguard public key)
	Id string

	//a connection stream to the Peer (gRPC or websocket)
	Stream Channel
}

// NewPeer creates a new instance of a Peer connected with gRPC
func NewPeer(id string, stream Channel) *Peer {
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
	log.Printf("registered peer [%s]", peer.Id)

}

// Deregister deregister Peer from the Registry (usually once it disconnects)
func (registry *Registry) Deregister(peer *Peer) {
	_, loaded := registry.Peers.LoadAndDelete(peer.Id)
	if loaded {
		log.Printf("deregistered peer [%s]", peer.Id)
	} else {
		log.Warnf("attempted to remove non-existent peer [%s]", peer.Id)
	}

}
