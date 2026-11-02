package server

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
	"golang.org/x/time/rate"

	"github.com/netbirdio/netbird/relay/healthcheck/peerid"
	"github.com/netbirdio/netbird/relay/protocol"
	"github.com/netbirdio/netbird/relay/server/listener"
	"github.com/netbirdio/netbird/shared/peerauth"
	"github.com/netbirdio/netbird/shared/relay/messages"

	//nolint:staticcheck
	"github.com/netbirdio/netbird/relay/metrics"
	"github.com/netbirdio/netbird/relay/server/store"
)

// misconfigLogInterval bounds the error logged for every peer retry while peer auth is misconfigured.
const misconfigLogInterval = time.Minute

type Listener interface {
	Bind() error
	Serve(func(conn listener.Conn)) error
	Shutdown(ctx context.Context) error
	Protocol() protocol.Protocol
}

type Config struct {
	Meter          metric.Meter
	ExposedAddress string
	TLSSupport     bool
	AuthValidator  Validator
	PeerAuth       PeerAuthConfig

	instanceURL url.URL
}

// PeerAuthConfig configures the verification of the tokens bound to the peer keys. With no keys,
// a peer presenting such a token is refused.
type PeerAuthConfig struct {
	Keys peerauth.TokenKeys
	// Hostnames, when set, are the only names accepted in proofs: the exposed address hostname
	// and any global name the relays share behind a load balancer. Empty skips the name check.
	Hostnames []string
	// Required refuses peers presenting no bound token.
	Required bool
	// CheckTime bounds the proof timestamp to peerauth.DefaultSkew from this Relay's clock. Off, a
	// proof is valid as long as its token, so peer clocks need not be in sync.
	CheckTime bool
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
	verifier      *peerauth.Verifier
	authRequired  bool
	misconfigLog  *rate.Sometimes

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

	verifier, err := newPeerAuthVerifier(config.PeerAuth, config.instanceURL)
	if err != nil {
		metricsCancel()
		return nil, fmt.Errorf("peer auth: %w", err)
	}

	r := &Relay{
		metrics:        m,
		metricsCancel:  metricsCancel,
		validator:      config.AuthValidator,
		verifier:       verifier,
		authRequired:   config.PeerAuth.Required,
		misconfigLog:   &rate.Sometimes{First: 1, Interval: misconfigLogInterval},
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
func (r *Relay) Accept(conn listener.Conn) {
	acceptTime := time.Now()
	r.closeMu.RLock()
	defer r.closeMu.RUnlock()
	if r.closed {
		if err := conn.Close(); err != nil {
			log.Debugf("failed to close connection after shutdown, %s: %s", conn.RemoteAddr(), err)
		}
		return
	}

	hsCtx, hsCancel := context.WithTimeout(context.Background(), handshakeTimeout)
	defer hsCancel()

	h := handshake{
		conn:        conn,
		validator:   r.validator,
		verifier:    r.verifier,
		required:    r.authRequired,
		preparedMsg: r.preparedMsg,
	}
	peerID, err := h.handshakeReceive(hsCtx)
	if err != nil {
		r.logHandshakeFailure(peerID, conn, err)
		if cErr := conn.Close(); cErr != nil {
			log.Errorf("failed to close connection, %s: %s", conn.RemoteAddr(), cErr)
		}
		return
	}

	if r.takesOverAuthenticatedPeer(*peerID, h.authenticated) {
		log.Infof("refused peer %s from %s: %s", peerID, conn.RemoteAddr(), store.ErrAuthenticatedPeerExists)
		if cErr := conn.Close(); cErr != nil {
			log.Errorf("failed to close connection, %s: %s", conn.RemoteAddr(), cErr)
		}
		return
	}

	if err := h.handshakeResponse(hsCtx); err != nil {
		log.Errorf("failed to send handshake response, close connection: %s", err)
		if cErr := conn.Close(); cErr != nil {
			log.Errorf("failed to close connection, %s: %s", conn.RemoteAddr(), cErr)
		}
		return
	}
	r.metrics.RecordAuthenticationTime(time.Since(acceptTime))

	peer := NewPeer(r.metrics, *peerID, h.selectedVersion, conn, r.store, r.notifier)
	peer.authenticated = h.authenticated
	storeTime := time.Now()
	isReconnection, err := r.store.AddPeer(peer)
	if err != nil {
		peer.log.Infof("refused peer from %s: %s", conn.RemoteAddr(), err)
		if cErr := conn.Close(); cErr != nil {
			log.Errorf("failed to close connection, %s: %s", conn.RemoteAddr(), cErr)
		}
		return
	}
	peer.log.Infof("peer connected from: %s, advertised protocol version: %d, selected: %d, authenticated: %t", conn.RemoteAddr(), h.advertisedVersion, h.selectedVersion, h.authenticated)
	if isReconnection {
		r.metrics.RecordPeerReconnection()
	}
	r.notifier.PeerCameOnline(peer.ID())

	transport := conn.Protocol()
	r.metrics.RecordPeerStoreTime(time.Since(storeTime))
	r.metrics.PeerConnected(peer.String(), transport)
	r.metrics.RecordProtocolVersion(h.advertisedVersion, h.selectedVersion)
	go func() {
		peer.Work()
		if deleted := r.store.DeletePeer(peer); deleted {
			r.notifier.PeerWentOffline(peer.ID())
		}
		peer.log.Debugf("relay connection closed")
		r.metrics.PeerDisconnected(peer.String(), transport)
	}()
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

// takesOverAuthenticatedPeer refuses a takeover before the handshake response, so the peer is not
// told it connected; AddPeer still refuses one racing in after this check.
func (r *Relay) takesOverAuthenticatedPeer(peerID messages.PeerID, authenticated bool) bool {
	if authenticated {
		return false
	}
	old, ok := r.store.Peer(peerID)
	return ok && old.Authenticated()
}

// newPeerAuthVerifier returns nil when no keys are configured: bound tokens are then refused.
func newPeerAuthVerifier(cfg PeerAuthConfig, instanceURL url.URL) (*peerauth.Verifier, error) {
	if len(cfg.Keys.Ed25519) == 0 {
		if cfg.Required {
			return nil, errors.New("peer auth required without Management public keys")
		}
		return nil, nil //nolint:nilnil // no keys: bound tokens are refused
	}
	if err := cfg.Keys.Validate(); err != nil {
		return nil, err
	}
	if err := peerauth.ValidateHostnames(cfg.Hostnames); err != nil {
		return nil, err
	}
	if len(cfg.Hostnames) > 0 && !slices.Contains(cfg.Hostnames, instanceURL.Hostname()) {
		log.Warnf("peer auth hostnames %v miss the exposed address hostname %s: peers dialing this instance directly will be refused",
			cfg.Hostnames, instanceURL.Hostname())
	}
	v := &peerauth.Verifier{Service: peerauth.ServiceRelay, Keys: cfg.Keys, Hostnames: cfg.Hostnames}
	if cfg.CheckTime {
		v.Skew = peerauth.DefaultSkew
	}
	return v, nil
}

// logHandshakeFailure logs refused peer auth credentials at debug when a peer repeats them on every
// retry (none, or an expired token), at info when they do not verify, and at error, once per
// interval, when this Relay lacks the keys to verify them.
func (r *Relay) logHandshakeFailure(peerID *messages.PeerID, conn listener.Conn, err error) {
	switch {
	case peerid.IsHealthCheck(peerID):
		log.Debugf("health check connection from %s", conn.RemoteAddr())
	case errors.Is(err, errPeerAuthRequired), errors.Is(err, peerauth.ErrTokenExpired):
		log.Debugf("refused peer: %s", err)
	case errors.Is(err, errPeerAuthNotConfigured):
		logged := false
		r.misconfigLog.Do(func() {
			logged = true
			log.Errorf("refused peer: %s", err)
		})
		if !logged {
			log.Debugf("refused peer: %s", err)
		}
	case errors.Is(err, peerauth.ErrStaleProof):
		log.Infof("refused peer, check the peer clock: %s", err)
	case errors.Is(err, errInvalidCredentials):
		log.Infof("refused peer: %s", err)
	default:
		log.Errorf("failed to handshake: %s", err)
	}
}
