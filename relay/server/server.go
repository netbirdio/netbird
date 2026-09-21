package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/url"
	"sync"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/relay/protocol"
	"github.com/netbirdio/netbird/relay/server/listener"
	"github.com/netbirdio/netbird/relay/server/listener/quic"
	"github.com/netbirdio/netbird/relay/server/listener/ws"
	quictls "github.com/netbirdio/netbird/shared/relay/tls"
	"github.com/netbirdio/netbird/trustedproxy"
)

// ListenerConfig is the configuration for the listener.
// Address: the address to bind the listener to. It could be an address behind a reverse proxy.
// TLSConfig: the TLS configuration for the listener.
// TrustedProxies: upstream proxy prefixes whose forwarding headers (X-Real-Ip/X-Real-Port) are trusted.
type ListenerConfig struct {
	Address        string
	TLSConfig      *tls.Config
	TrustedProxies *trustedproxy.List
}

// Server is the main entry point for the relay server.
// It is the gate between the WebSocket listener and the Relay server logic.
// In a new HTTP connection, the server will accept the connection and pass it to the Relay server via the Accept method.
type Server struct {
	relay       *Relay
	listeners   []Listener
	listenerMux sync.Mutex
	closed      bool
}

// NewServer creates and returns a new relay server instance.
//
// Parameters:
//
//	config: A Config struct containing the necessary configuration:
//	  - Meter: An OpenTelemetry metric.Meter used for recording metrics. If nil, a default no-op meter is used.
//	  - InstanceURL: The public address (in domain:port format) used as the server's instance URL. Required.
//	  - TLSSupport: A boolean indicating whether TLS is enabled for the server.
//	  - AuthValidator: A Validator used to authenticate peers. Required.
//
// Returns:
//
//	A pointer to a Server instance and an error. If the configuration is valid and initialization succeeds,
//	the returned error will be nil. Otherwise, the error will describe the problem.
func NewServer(config Config) (*Server, error) {
	relay, err := NewRelay(config)
	if err != nil {
		return nil, err
	}
	return &Server{
		relay:     relay,
		listeners: make([]Listener, 0, 2),
	}, nil
}

// Listen binds the relay listeners and serves them until Shutdown is called.
func (r *Server) Listen(cfg ListenerConfig) error {
	r.listenerMux.Lock()
	if r.closed {
		r.listenerMux.Unlock()
		return nil
	}

	listeners, err := bindListeners(newListeners(cfg))
	if err != nil {
		r.listenerMux.Unlock()
		return err
	}
	r.listeners = append(r.listeners, listeners...)

	errChan := make(chan error, len(listeners))
	wg := sync.WaitGroup{}
	for _, l := range listeners {
		wg.Add(1)
		go func(listener Listener) {
			defer wg.Done()
			errChan <- listener.Serve(r.relay.Accept)
		}(l)
	}
	r.listenerMux.Unlock()

	wg.Wait()
	close(errChan)
	var multiErr *multierror.Error
	for err := range errChan {
		multiErr = multierror.Append(multiErr, err)
	}

	return nberrors.FormatErrorOrNil(multiErr)
}

// Shutdown stops the relay server. If there are active connections, they will be closed gracefully. In case of a context,
// the connections will be forcefully closed.
func (r *Server) Shutdown(ctx context.Context) error {
	r.relay.Shutdown(ctx)

	r.listenerMux.Lock()
	defer r.listenerMux.Unlock()

	r.closed = true
	err := shutdownListeners(ctx, r.listeners)
	r.listeners = r.listeners[:0]
	return err
}

func (r *Server) ListenerProtocols() []protocol.Protocol {
	result := make([]protocol.Protocol, 0)

	r.listenerMux.Lock()
	for _, l := range r.listeners {
		result = append(result, l.Protocol())
	}
	r.listenerMux.Unlock()
	return result
}

func (r *Server) InstanceURL() url.URL {
	return r.relay.InstanceURL()
}

// RelayAccept returns the relay's Accept function for handling incoming connections.
// This allows external HTTP handlers to route connections to the relay without
// starting the relay's own listeners.
func (r *Server) RelayAccept() func(conn listener.Conn) {
	return r.relay.Accept
}

func newListeners(cfg ListenerConfig) []Listener {
	listeners := []Listener{
		&ws.Listener{
			Address:        cfg.Address,
			TLSConfig:      cfg.TLSConfig,
			TrustedProxies: cfg.TrustedProxies,
		},
	}

	tlsConfigQUIC, err := quictls.ServerQUICTLSConfig(cfg.TLSConfig)
	if err != nil {
		log.Warnf("Not starting QUIC listener: %v", err)
		return listeners
	}

	return append(listeners, &quic.Listener{
		Address:   cfg.Address,
		TLSConfig: tlsConfigQUIC,
	})
}

func bindListeners(listeners []Listener) ([]Listener, error) {
	bound := make([]Listener, 0, len(listeners))
	for _, l := range listeners {
		if err := l.Bind(); err != nil {
			if shutdownErr := shutdownListeners(context.Background(), bound); shutdownErr != nil {
				log.Warnf("failed to close listeners after bind error: %v", shutdownErr)
			}
			return nil, fmt.Errorf("%s listener: %w", l.Protocol(), err)
		}
		bound = append(bound, l)
	}
	return bound, nil
}

func shutdownListeners(ctx context.Context, listeners []Listener) error {
	var multiErr *multierror.Error
	for _, l := range listeners {
		if err := l.Shutdown(ctx); err != nil {
			multiErr = multierror.Append(multiErr, err)
		}
	}
	return nberrors.FormatErrorOrNil(multiErr)
}
