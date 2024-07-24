package server

import (
	"context"
	"fmt"
	"net"
	"sync"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/metric"

	"github.com/netbirdio/netbird/relay/auth"
	"github.com/netbirdio/netbird/relay/messages"
	"github.com/netbirdio/netbird/relay/metrics"
)

type Relay struct {
	metrics   *metrics.Metrics
	validator auth.Validator

	store      *Store
	instaceURL string

	closed  bool
	closeMu sync.RWMutex
}

func NewRelay(meter metric.Meter, exposedAddress string, tlsSupport bool, validator auth.Validator) (*Relay, error) {
	m, err := metrics.NewMetrics(meter)
	if err != nil {
		return nil, fmt.Errorf("creating app metrics: %v", err)
	}

	r := &Relay{
		metrics:   m,
		validator: validator,
		store:     NewStore(),
	}

	if tlsSupport {
		r.instaceURL = fmt.Sprintf("rels://%s", exposedAddress)
	} else {
		r.instaceURL = fmt.Sprintf("rel://%s", exposedAddress)
	}

	return r, nil
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
	r.metrics.Peers.Add(context.Background(), 1)
	go func() {
		peer.Work()
		r.store.DeletePeer(peer)
		peer.log.Debugf("relay connection closed")
		r.metrics.Peers.Add(context.Background(), -1)
	}()
}

func (r *Relay) Close(ctx context.Context) {
	log.Infof("close connection with all peers")
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

	peerID, authPayload, err := messages.UnmarshalHelloMsg(buf[:n])
	if err != nil {
		log.Errorf("failed to handshake: %s", err)
		return nil, err
	}

	if err := r.validator.Validate(authPayload); err != nil {
		log.Errorf("failed to authenticate connection: %s", err)
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
