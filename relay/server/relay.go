package server

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/metric"

	"github.com/netbirdio/netbird/relay/auth"
	//nolint:staticcheck
	"github.com/netbirdio/netbird/relay/metrics"
)

// Relay represents the relay server
type Relay struct {
	metrics       *metrics.Metrics
	metricsCancel context.CancelFunc
	validator     auth.Validator

	store       *Store
	instanceURL string
	preparedMsg *preparedMsg

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

	r.instanceURL, err = getInstanceURL(exposedAddress, tlsSupport)
	if err != nil {
		metricsCancel()
		return nil, fmt.Errorf("get instance URL: %v", err)
	}

	r.preparedMsg, err = newPreparedMsg(r.instanceURL)
	if err != nil {
		metricsCancel()
		return nil, fmt.Errorf("prepare message: %v", err)
	}

	return r, nil
}

// getInstanceURL checks if user supplied a URL scheme otherwise adds to the
// provided address according to TLS definition and parses the address before returning it
func getInstanceURL(exposedAddress string, tlsSupported bool) (string, error) {
	addr := exposedAddress
	split := strings.Split(exposedAddress, "://")
	switch {
	case len(split) == 1 && tlsSupported:
		addr = "rels://" + exposedAddress
	case len(split) == 1 && !tlsSupported:
		addr = "rel://" + exposedAddress
	case len(split) > 2:
		return "", fmt.Errorf("invalid exposed address: %s", exposedAddress)
	}

	parsedURL, err := url.ParseRequestURI(addr)
	if err != nil {
		return "", fmt.Errorf("invalid exposed address: %v", err)
	}

	if parsedURL.Scheme != "rel" && parsedURL.Scheme != "rels" {
		return "", fmt.Errorf("invalid scheme: %s", parsedURL.Scheme)
	}

	return parsedURL.String(), nil
}

// Accept start to handle a new peer connection
func (r *Relay) Accept(conn net.Conn) {
	acceptTime := time.Now()
	r.closeMu.RLock()
	defer r.closeMu.RUnlock()
	if r.closed {
		return
	}

	h := handshake{
		conn:        conn,
		validator:   r.validator,
		preparedMsg: r.preparedMsg,
	}
	peerID, err := h.handshakeReceive()
	if err != nil {
		log.Errorf("failed to handshake: %s", err)
		if cErr := conn.Close(); cErr != nil {
			log.Errorf("failed to close connection, %s: %s", conn.RemoteAddr(), cErr)
		}
		return
	}

	peer := NewPeer(r.metrics, peerID, conn, r.store)
	peer.log.Infof("peer connected from: %s", conn.RemoteAddr())
	storeTime := time.Now()
	r.store.AddPeer(peer)
	r.metrics.RecordPeerStoreTime(time.Since(storeTime))
	r.metrics.PeerConnected(peer.String())
	go func() {
		peer.Work()
		r.store.DeletePeer(peer)
		peer.log.Debugf("relay connection closed")
		r.metrics.PeerDisconnected(peer.String())
	}()

	if err := h.handshakeResponse(); err != nil {
		log.Errorf("failed to send handshake response, close peer: %s", err)
		peer.Close()
	}
	r.metrics.RecordAuthenticationTime(time.Since(acceptTime))
}

// Shutdown closes the relay server
// It closes the connection with all peers in gracefully and stops accepting new connections.
func (r *Relay) Shutdown(ctx context.Context) {
	log.Infof("close connection with all peers")
	r.closeMu.Lock()
	defer r.closeMu.Unlock()

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
	r.closed = true
}

// InstanceURL returns the instance URL of the relay server
func (r *Relay) InstanceURL() string {
	return r.instanceURL
}
