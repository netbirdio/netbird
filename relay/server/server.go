package server

import (
	"context"
	"crypto/tls"
	"time"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/metric"

	"github.com/netbirdio/netbird/relay/auth"
	"github.com/netbirdio/netbird/relay/server/listener"
	"github.com/netbirdio/netbird/relay/server/listener/ws"
)

type ListenerConfig struct {
	Address   string
	TLSConfig *tls.Config
}

type Server struct {
	relay      *Relay
	wSListener listener.Listener
}

func NewServer(meter metric.Meter, exposedAddress string, tlsSupport bool, authValidator auth.Validator) (*Server, error) {
	relay, err := NewRelay(meter, exposedAddress, tlsSupport, authValidator)
	if err != nil {
		return nil, err
	}
	return &Server{
		relay: relay,
	}, nil
}

func (r *Server) Listen(cfg ListenerConfig) error {
	r.wSListener = &ws.Listener{
		Address:   cfg.Address,
		TLSConfig: cfg.TLSConfig,
	}

	var wslErr error
	go func() {
		wslErr = r.wSListener.Listen(r.relay.Accept)
		if wslErr != nil {
			log.Errorf("failed to bind ws server: %s", wslErr)
		}
	}()

	return wslErr
}

func (r *Server) Close() (err error) {
	// stop service new connections
	if r.wSListener != nil {
		err = r.wSListener.Close()
	}

	// close accepted connections gracefully
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r.relay.Close(ctx)
	return
}

func (r *Server) InstanceURL() string {
	return r.relay.instanceURL
}
