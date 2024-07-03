package server

import (
	"context"
	"fmt"
	"net"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/relay/messages"
)

type Relay struct {
	store      *Store
	instaceURL string // domain:port

	closed  bool
	closeMu sync.RWMutex
}

func NewRelay(exposedAddress string, tlsSupport bool) *Relay {
	r := &Relay{
		store: NewStore(),
	}

	if tlsSupport {
		r.instaceURL = fmt.Sprintf("rels://%s", exposedAddress)
	} else {
		r.instaceURL = fmt.Sprintf("rel://%s", exposedAddress)
	}
	return r
}

func (r *Relay) Accept(conn net.Conn) {
	r.closeMu.RLock()
	defer r.closeMu.RUnlock()
	if r.closed {
		return
	}

	peerID, err := r.handShake(conn)
	if err != nil {
		log.Errorf("failed to handshake with %s: %s", conn.RemoteAddr(), err)
		cErr := conn.Close()
		if cErr != nil {
			log.Errorf("failed to close connection, %s: %s", conn.RemoteAddr(), cErr)
		}
		return
	}

	peer := NewPeer(peerID, conn, r.store)
	peer.log.Infof("peer connected from: %s", conn.RemoteAddr())
	r.store.AddPeer(peer)

	go func() {
		peer.Work()
		r.store.DeletePeer(peer)
		peer.log.Debugf("relay connection closed")
	}()
}

func (r *Relay) Close(ctx context.Context) {
	log.Infof("closeing connection with all peers")
	r.closeMu.Lock()
	wg := sync.WaitGroup{}
	peers := r.store.Peers()
	for _, peer := range peers {
		wg.Add(1)
		go func(p *Peer) {
			p.CloseGracefully(ctx)
			wg.Done()
		}(peer)
	}
	wg.Wait()
	r.closeMu.Unlock()
}

func (r *Relay) handShake(conn net.Conn) ([]byte, error) {
	buf := make([]byte, messages.MaxHandshakeSize)
	n, err := conn.Read(buf)
	if err != nil {
		log.Errorf("failed to read message: %s", err)
		return nil, err
	}
	msgType, err := messages.DetermineClientMsgType(buf[:n])
	if err != nil {
		return nil, err
	}

	if msgType != messages.MsgTypeHello {
		tErr := fmt.Errorf("invalid message type")
		log.Errorf("failed to handshake: %s", tErr)
		return nil, tErr
	}

	peerID, err := messages.UnmarshalHelloMsg(buf[:n])
	if err != nil {
		log.Errorf("failed to handshake: %s", err)
		return nil, err
	}

	msg, _ := messages.MarshalHelloResponse(r.instaceURL)
	_, err = conn.Write(msg)
	if err != nil {
		return nil, err
	}
	return peerID, nil
}

func (r *Relay) InstanceURL() string {
	return r.instaceURL
}
