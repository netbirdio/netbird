package server

import (
	"context"
	"crypto/tls"
	"sync"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/metric"

	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/relay/auth"
	"github.com/netbirdio/netbird/relay/server/listener"
	"github.com/netbirdio/netbird/relay/server/listener/quic"
	"github.com/netbirdio/netbird/relay/server/listener/ws"
	quictls "github.com/netbirdio/netbird/relay/tls"
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
	relay     *Relay
	listeners []listener.Listener
}

// NewServer creates a new relay server instance.
// meter: the OpenTelemetry meter
// exposedAddress: this address will be used as the instance URL. It should be a domain:port format.
// tlsSupport: if true, the server will support TLS
// authValidator: the auth validator to use for the server
func NewServer(meter metric.Meter, exposedAddress string, tlsSupport bool, authValidator auth.Validator) (*Server, error) {
	relay, err := NewRelay(meter, exposedAddress, tlsSupport, authValidator)
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

	var multiErr *multierror.Error
	for _, l := range r.listeners {
		if err := l.Shutdown(ctx); err != nil {
			multiErr = multierror.Append(multiErr, err)
		}
	}
	return nberrors.FormatErrorOrNil(multiErr)
}

// InstanceURL returns the instance URL of the relay server.
func (r *Server) InstanceURL() string {
	return r.relay.instanceURL
}
