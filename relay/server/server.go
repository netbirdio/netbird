package server

import (
	"context"
	"crypto/tls"
	"net"
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
)

// ListenerConfig is the configuration for the listener.
// Address: the address to bind the listener to. It could be an address behind a reverse proxy.
// TLSConfig: the TLS configuration for the listener.
type ListenerConfig struct {
	Address   string
	TLSConfig *tls.Config
}

// Server is the main entry point for the relay server.
// It is the gate between the WebSocket listener and the Relay server logic.
// In a new HTTP connection, the server will accept the connection and pass it to the Relay server via the Accept method.
type Server struct {
	relay       *Relay
	listeners   []listener.Listener
	listenerMux sync.Mutex
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
		listeners: make([]listener.Listener, 0, 2),
	}, nil
}

// Listen starts the relay server.
func (r *Server) Listen(cfg ListenerConfig) error {
	wSListener := &ws.Listener{
		Address:   cfg.Address,
		TLSConfig: cfg.TLSConfig,
	}

	r.listenerMux.Lock()
	r.listeners = append(r.listeners, wSListener)

	tlsConfigQUIC, err := quictls.ServerQUICTLSConfig(cfg.TLSConfig)
	if err != nil {
		log.Warnf("Not starting QUIC listener: %v", err)
	} else {
		quicListener := &quic.Listener{
			Address:   cfg.Address,
			TLSConfig: tlsConfigQUIC,
		}

		r.listeners = append(r.listeners, quicListener)
	}

	errChan := make(chan error, len(r.listeners))
	wg := sync.WaitGroup{}
	for _, l := range r.listeners {
		wg.Add(1)
		go func(listener listener.Listener) {
			defer wg.Done()
			errChan <- listener.Listen(r.relay.Accept)
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
	var multiErr *multierror.Error
	for _, l := range r.listeners {
		if err := l.Shutdown(ctx); err != nil {
			multiErr = multierror.Append(multiErr, err)
		}
	}
	r.listeners = r.listeners[:0]
	r.listenerMux.Unlock()
	return nberrors.FormatErrorOrNil(multiErr)
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
func (r *Server) RelayAccept() func(conn net.Conn) {
	return r.relay.Accept
}
