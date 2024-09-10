package server

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/metric"

	"github.com/netbirdio/netbird/relay/auth"
	"github.com/netbirdio/netbird/relay/messages"
	"github.com/netbirdio/netbird/relay/messages/address"
	authmsg "github.com/netbirdio/netbird/relay/messages/auth"
	"github.com/netbirdio/netbird/relay/metrics"
)

// Relay represents the relay server
type Relay struct {
	metrics       *metrics.Metrics
	metricsCancel context.CancelFunc
	validator     auth.Validator
	validatorV2   auth.Validator

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
// validatorV2: An instance of authv2.Validator from the auth/hmac/v2 package. It is used to validate the authentication
// of the peers for the auth message.
//
// Returns:
// A pointer to a Relay instance and an error. If the Relay instance is successfully created, the error is nil.
// Otherwise, the error contains the details of what went wrong.
func NewRelay(meter metric.Meter, exposedAddress string, tlsSupport bool, validator auth.Validator, validatorV2 auth.Validator) (*Relay, error) {
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
		validatorV2:   validatorV2,
		store:         NewStore(),
	}

	r.instanceURL, err = getInstanceURL(exposedAddress, tlsSupport)
	if err != nil {
		metricsCancel()
		return nil, fmt.Errorf("get instance URL: %v", err)
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
	r.closeMu.RLock()
	defer r.closeMu.RUnlock()
	if r.closed {
		return
	}

	peerID, err := r.handshake(conn)
	if err != nil {
		log.Errorf("failed to handshake: %s", err)
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
		return nil, fmt.Errorf("read from %s: %w", conn.RemoteAddr(), err)
	}

	_, err = messages.ValidateVersion(buf[:n])
	if err != nil {
		return nil, fmt.Errorf("validate version from %s: %w", conn.RemoteAddr(), err)
	}

	msgType, err := messages.DetermineClientMessageType(buf[messages.SizeOfVersionByte:n])
	if err != nil {
		return nil, fmt.Errorf("determine message type from %s: %w", conn.RemoteAddr(), err)
	}

	var (
		responseMsg []byte
		peerID      []byte
	)
	switch msgType {
	case messages.MsgTypeHello:
		responseMsg, err = r.handleHelloMsg(buf[messages.SizeOfProtoHeader:n], conn.RemoteAddr())
	case messages.MsgTypeAuth:
		responseMsg, err = r.handleAuthMsg(buf[messages.SizeOfProtoHeader:n], conn.RemoteAddr())
	default:
		return nil, fmt.Errorf("invalid message type %d from %s", msgType, conn.RemoteAddr())
	}
	if err != nil {
		return nil, err
	}

	_, err = conn.Write(responseMsg)
	if err != nil {
		return nil, fmt.Errorf("write to %s (%s): %w", peerID, conn.RemoteAddr(), err)
	}

	return peerID, nil
}

func (r *Relay) handleHelloMsg(buf []byte, remoteAddr net.Addr) ([]byte, error) {
	peerID, authData, err := messages.UnmarshalHelloMsg(buf)
	if err != nil {
		return nil, fmt.Errorf("unmarshal hello message: %w", err)
	}
	log.Warnf("peer is using depracated initial message type: %s (%s)", peerID, remoteAddr)

	authMsg, err := authmsg.UnmarshalMsg(authData)
	if err != nil {
		return nil, fmt.Errorf("unmarshal auth message: %w", err)
	}

	if err := r.validator.Validate(authMsg.AdditionalData); err != nil {
		return nil, fmt.Errorf("validate %s (%s): %w", peerID, remoteAddr, err)
	}

	addr := &address.Address{URL: r.instanceURL}
	addrData, err := addr.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal addressc to %s (%s): %w", peerID, remoteAddr, err)
	}

	responseMsg, err := messages.MarshalHelloResponse(addrData)
	if err != nil {
		return nil, fmt.Errorf("marshal hello response to %s (%s): %w", peerID, remoteAddr, err)
	}
	return responseMsg, nil
}

func (r *Relay) handleAuthMsg(buf []byte, addr net.Addr) ([]byte, error) {
	peerID, authPayload, err := messages.UnmarshalAuthMsg(buf)
	if err != nil {
		return nil, fmt.Errorf("unmarshal hello message: %w", err)
	}

	if err := r.validatorV2.Validate(authPayload); err != nil {
		return nil, fmt.Errorf("validate %s (%s): %w", peerID, addr, err)
	}

	responseMsg, err := messages.MarshalAuthResponse(r.instanceURL)
	if err != nil {
		return nil, fmt.Errorf("marshal hello response to %s (%s): %w", peerID, addr, err)
	}
	return responseMsg, nil
}
