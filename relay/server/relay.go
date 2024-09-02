package server

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"sync"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/metric"

	"github.com/netbirdio/netbird/relay/auth"
	"github.com/netbirdio/netbird/relay/messages"
	"github.com/netbirdio/netbird/relay/metrics"
)

// Relay represents the relay server
type Relay struct {
	metrics       *metrics.Metrics
	metricsCancel context.CancelFunc
	validator     auth.Validator

	store       *Store
	instanceURL string

	closed  bool
	closeMu sync.RWMutex
}

// NewRelay creates a new Relay instance
//
// Parameters:
// meter: An instance of metric.Meter from the go.opentelemetry.io/otel/metric package. It is used to create and manage
// metrics for the relay server.
// exposedAddress: A string representing the address that the relay server is exposed on. The client will use this
// address as the relay server's instance URL.
// tlsSupport: A boolean indicating whether the relay server supports TLS (Transport Layer Security) or not. The
// instance URL depends on this value.
// validator: An instance of auth.Validator from the auth package. It is used to validate the authentication of the
// peers.
//
// Returns:
// A pointer to a Relay instance and an error. If the Relay instance is successfully created, the error is nil.
// Otherwise, the error contains the details of what went wrong.
func NewRelay(meter metric.Meter, exposedAddress string, tlsSupport bool, validator auth.Validator) (*Relay, error) {
	ctx, metricsCancel := context.WithCancel(context.Background())
	m, err := metrics.NewMetrics(ctx, meter)
	if err != nil {
		metricsCancel()
		return nil, fmt.Errorf("creating app metrics: %v", err)
	}

	r := &Relay{
		metrics:       m,
		metricsCancel: metricsCancel,
		validator:     validator,
		store:         NewStore(),
	}

	if tlsSupport {
		r.instanceURL = fmt.Sprintf("rels://%s", exposedAddress)
	} else {
		r.instanceURL = fmt.Sprintf("rel://%s", exposedAddress)
	}
	_, err = url.ParseRequestURI(r.instanceURL)
	if err != nil {
		return nil, fmt.Errorf("invalid exposed address: %v", err)
	}

	return r, nil
}

// Accept start to handle a new peer connection
func (r *Relay) Accept(conn net.Conn) {
	r.closeMu.RLock()
	defer r.closeMu.RUnlock()
	if r.closed {
		return
	}

	peerID, err := r.handshake(conn)
	if err != nil {
		log.Errorf("failed to handshake with %s: %s", conn.RemoteAddr(), err)
		cErr := conn.Close()
		if cErr != nil {
			log.Errorf("failed to close connection, %s: %s", conn.RemoteAddr(), cErr)
		}
		return
	}

	peer := NewPeer(r.metrics, peerID, conn, r.store)
	peer.log.Infof("peer connected from: %s", conn.RemoteAddr())
	r.store.AddPeer(peer)
	r.metrics.PeerConnected(peer.String())
	go func() {
		peer.Work()
		r.store.DeletePeer(peer)
		peer.log.Debugf("relay connection closed")
		r.metrics.PeerDisconnected(peer.String())
	}()
}

// Shutdown closes the relay server
// It closes the connection with all peers in gracefully and stops accepting new connections.
func (r *Relay) Shutdown(ctx context.Context) {
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
	r.metricsCancel()
	r.closeMu.Unlock()
}

// InstanceURL returns the instance URL of the relay server
func (r *Relay) InstanceURL() string {
	return r.instanceURL
}

func (r *Relay) handshake(conn net.Conn) ([]byte, error) {
	buf := make([]byte, messages.MaxHandshakeSize)
	n, err := conn.Read(buf)
	if err != nil {
		log.Debugf("failed to read message from: %s, %s", conn.RemoteAddr(), err)
		return nil, err
	}
	msgType, err := messages.DetermineClientMsgType(buf[:n])
	if err != nil {
		return nil, err
	}

	if msgType != messages.MsgTypeHello {
		tErr := fmt.Errorf("invalid message type")
		log.Debugf("failed to handshake with: %s, %s", conn.RemoteAddr(), tErr)
		return nil, tErr
	}

	peerID, authPayload, err := messages.UnmarshalHelloMsg(buf[:n])
	if err != nil {
		log.Debugf("failed to handshake with: %s, %s", conn.RemoteAddr(), err)
		return nil, err
	}

	if err := r.validator.Validate(authPayload); err != nil {
		log.Debugf("failed to authenticate connection with: %s, %s", conn.RemoteAddr(), err)
		return nil, err
	}

	msg, _ := messages.MarshalHelloResponse(r.instanceURL)
	_, err = conn.Write(msg)
	if err != nil {
		return nil, err
	}
	return peerID, nil
}
