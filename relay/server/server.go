package server

import (
	"context"
	"crypto/tls"
	"errors"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/metric"

	"github.com/netbirdio/netbird/relay/auth"
	"github.com/netbirdio/netbird/relay/server/listener"
	"github.com/netbirdio/netbird/relay/server/listener/udp"
	"github.com/netbirdio/netbird/relay/server/listener/ws"
)

type ListenerConfig struct {
	Address   string
	TLSConfig *tls.Config
}

type Server struct {
	relay       *Relay
	uDPListener listener.Listener
	wSListener  listener.Listener
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
	wg := sync.WaitGroup{}
	wg.Add(2)

	r.wSListener = &ws.Listener{
		Address:   cfg.Address,
		TLSConfig: cfg.TLSConfig,
	}

	var wslErr error
	go func() {
		defer wg.Done()
		wslErr = r.wSListener.Listen(r.relay.Accept)
		if wslErr != nil {
			log.Errorf("failed to bind ws server: %s", wslErr)
		}
	}()

	r.uDPListener = udp.NewListener(cfg.Address)
	var udpLErr error
	go func() {
		defer wg.Done()
		udpLErr = r.uDPListener.Listen(r.relay.Accept)
		if udpLErr != nil {
			log.Errorf("failed to bind ws server: %s", udpLErr)
		}
	}()

	err := errors.Join(wslErr, udpLErr)
	return err
}

func (r *Server) Close() error {
	var wErr error
	// stop service new connections
	if r.wSListener != nil {
		wErr = r.wSListener.Close()
	}

	var uErr error
	if r.uDPListener != nil {
		uErr = r.uDPListener.Close()
	}

	// close accepted connections gracefully
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r.relay.Close(ctx)

	err := errors.Join(wErr, uErr)
	return err
}

func (r *Server) InstanceURL() string {
	return r.relay.instanceURL
}
