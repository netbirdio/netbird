package server

import (
	"context"
	"errors"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/relay/server/listener"
	"github.com/netbirdio/netbird/relay/server/listener/udp"
	"github.com/netbirdio/netbird/relay/server/listener/ws"
)

type Server struct {
	relay       *Relay
	uDPListener listener.Listener
	wSListener  listener.Listener
}

func NewServer() *Server {
	return &Server{
		relay: NewRelay(),
	}
}

func (r *Server) Listen(address string) error {
	wg := sync.WaitGroup{}
	wg.Add(2)

	r.wSListener = ws.NewListener(address)
	var wslErr error
	go func() {
		defer wg.Done()
		wslErr = r.wSListener.Listen(r.relay.Accept)
		if wslErr != nil {
			log.Errorf("failed to bind ws server: %s", wslErr)
		}
	}()

	r.uDPListener = udp.NewListener(address)
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
