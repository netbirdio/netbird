package ws

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"

	log "github.com/sirupsen/logrus"
	"nhooyr.io/websocket"
)

type Listener struct {
	// Address is the address to listen on.
	Address string
	// TLSConfig is the TLS configuration for the server.
	TLSConfig *tls.Config

	server   *http.Server
	acceptFn func(conn net.Conn)
}

func (l *Listener) Listen(acceptFn func(conn net.Conn)) error {
	l.acceptFn = acceptFn
	mux := http.NewServeMux()
	mux.HandleFunc("/", l.onAccept)

	l.server = &http.Server{
		Addr:      l.Address,
		Handler:   mux,
		TLSConfig: l.TLSConfig,
	}

	log.Infof("WS server listening address: %s", l.Address)
	var err error
	if l.TLSConfig != nil {
		err = l.server.ListenAndServeTLS("", "")
	} else {
		err = l.server.ListenAndServe()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (l *Listener) Shutdown(ctx context.Context) error {
	if l.server == nil {
		return nil
	}

	log.Infof("stop WS listener")
	if err := l.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("server shutdown failed: %v", err)
	}
	log.Infof("WS listener stopped")
	return nil
}

func (l *Listener) onAccept(w http.ResponseWriter, r *http.Request) {
	wsConn, err := websocket.Accept(w, r, nil)
	if err != nil {
		log.Errorf("failed to accept ws connection from %s: %s", r.RemoteAddr, err)
		return
	}

	rAddr, err := net.ResolveTCPAddr("tcp", r.RemoteAddr)
	if err != nil {
		err = wsConn.Close(websocket.StatusInternalError, "internal error")
		if err != nil {
			log.Errorf("failed to close ws connection: %s", err)
		}
		return
	}

	lAddr, err := net.ResolveTCPAddr("tcp", l.server.Addr)
	if err != nil {
		err = wsConn.Close(websocket.StatusInternalError, "internal error")
		if err != nil {
			log.Errorf("failed to close ws connection: %s", err)
		}
		return
	}

	conn := NewConn(wsConn, lAddr, rAddr)
	l.acceptFn(conn)
}
