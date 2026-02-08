package server

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"

	"github.com/netbirdio/netbird/relay/healthcheck/peerid"
	//nolint:staticcheck
	"github.com/netbirdio/netbird/relay/metrics"
	"github.com/netbirdio/netbird/relay/server/store"
)

type Config struct {
	Meter          metric.Meter
	ExposedAddress string
	TLSSupport     bool
	AuthValidator  Validator

	instanceURL url.URL
}

func (c *Config) validate() error {
	if c.Meter == nil {
		c.Meter = otel.Meter("")
	}
	if c.ExposedAddress == "" {
		return fmt.Errorf("exposed address is required")
	}

	instanceURL, err := getInstanceURL(c.ExposedAddress, c.TLSSupport)
	if err != nil {
		return fmt.Errorf("invalid url: %v", err)
	}
	c.instanceURL = *instanceURL

	if c.AuthValidator == nil {
		return fmt.Errorf("auth validator is required")
	}
	return nil
}

// Relay represents the relay server
type Relay struct {
	metrics       *metrics.Metrics
	metricsCancel context.CancelFunc
	validator     Validator

	store          *store.Store
	notifier       *store.PeerNotifier
	instanceURL    url.URL
	exposedAddress string
	preparedMsg    *preparedMsg

	closed  bool
	closeMu sync.RWMutex
}

// NewRelay creates and returns a new Relay instance.
//
// Parameters:
//
//	config: A Config struct that holds the configuration needed to initialize the relay server.
//	  - Meter: A metric.Meter used for emitting metrics. If not set, a default no-op meter will be used.
//	  - ExposedAddress: The external address clients use to reach this relay. Required.
//	  - TLSSupport: A boolean indicating if the relay uses TLS. Affects the generated instance URL.
//	  - AuthValidator: A Validator implementation used to authenticate peers. Required.
//
// Returns:
//
//	A pointer to a Relay instance and an error. If initialization is successful, the error will be nil;
//	otherwise, it will contain the reason the relay could not be created (e.g., invalid configuration).
func NewRelay(config Config) (*Relay, error) {
	if err := config.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %v", err)
	}

	ctx, metricsCancel := context.WithCancel(context.Background())
	m, err := metrics.NewMetrics(ctx, config.Meter)
	if err != nil {
		metricsCancel()
		return nil, fmt.Errorf("creating app metrics: %v", err)
	}

	r := &Relay{
		metrics:        m,
		metricsCancel:  metricsCancel,
		validator:      config.AuthValidator,
		instanceURL:    config.instanceURL,
		exposedAddress: config.ExposedAddress,
		store:          store.NewStore(),
		notifier:       store.NewPeerNotifier(),
	}

	r.preparedMsg, err = newPreparedMsg(r.instanceURL.String())
	if err != nil {
		metricsCancel()
		return nil, fmt.Errorf("prepare message: %v", err)
	}

	return r, nil
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
		if peerid.IsHealthCheck(peerID) {
			log.Debugf("health check connection from %s", conn.RemoteAddr())
		} else {
			log.Errorf("failed to handshake: %s", err)
		}
		if cErr := conn.Close(); cErr != nil {
			log.Errorf("failed to close connection, %s: %s", conn.RemoteAddr(), cErr)
		}
		return
	}

	peer := NewPeer(r.metrics, *peerID, conn, r.store, r.notifier)
	peer.log.Infof("peer connected from: %s", conn.RemoteAddr())
	storeTime := time.Now()
	if isReconnection := r.store.AddPeer(peer); isReconnection {
		r.metrics.RecordPeerReconnection()
	}
	r.notifier.PeerCameOnline(peer.ID())

	r.metrics.RecordPeerStoreTime(time.Since(storeTime))
	r.metrics.PeerConnected(peer.String())
	go func() {
		peer.Work()
		if deleted := r.store.DeletePeer(peer); deleted {
			r.notifier.PeerWentOffline(peer.ID())
		}
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
	for _, v := range peers {
		wg.Add(1)
		go func(p *Peer) {
			p.CloseGracefully(ctx)
			wg.Done()
		}(v.(*Peer))
	}
	wg.Wait()
	r.metricsCancel()
	r.closed = true
}

// InstanceURL returns the instance URL of the relay server
func (r *Relay) InstanceURL() url.URL {
	return r.instanceURL
}
