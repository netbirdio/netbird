package server

import (
	"context"
	"crypto/tls"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/metric"

	"github.com/netbirdio/netbird/relay/auth"
	"github.com/netbirdio/netbird/relay/server/listener"
	"github.com/netbirdio/netbird/relay/server/listener/ws"
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
	relay      *Relay
	wSListener listener.Listener
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
		relay: relay,
	}, nil
}

// Listen starts the relay server.
func (r *Server) Listen(cfg ListenerConfig) error {
	r.wSListener = &ws.Listener{
		Address:   cfg.Address,
		TLSConfig: cfg.TLSConfig,
	}

	wslErr := r.wSListener.Listen(r.relay.Accept)
	if wslErr != nil {
		log.Errorf("failed to bind ws server: %s", wslErr)
	}

	return wslErr
}

// Shutdown stops the relay server. If there are active connections, they will be closed gracefully. In case of a context,
// the connections will be forcefully closed.
func (r *Server) Shutdown(ctx context.Context) (err error) {
	// stop service new connections
	if r.wSListener != nil {
		err = r.wSListener.Shutdown(ctx)
	}

	r.relay.Shutdown(ctx)
	return
}

// InstanceURL returns the instance URL of the relay server.
func (r *Server) InstanceURL() string {
	return r.relay.instanceURL
}
