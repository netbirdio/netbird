package ws

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"nhooyr.io/websocket"

	"github.com/netbirdio/netbird/relay/server/listener"
)

type Listener struct {
	address string

	wg       sync.WaitGroup
	server   *http.Server
	acceptFn func(conn net.Conn)
}

func NewListener(address string) listener.Listener {
	return &Listener{
		address: address,
	}
}

// Listen todo: prevent multiple call
func (l *Listener) Listen(acceptFn func(conn net.Conn)) error {
	l.acceptFn = acceptFn
	mux := http.NewServeMux()
	mux.HandleFunc("/", l.onAccept)

	l.server = &http.Server{
		Addr:    l.address,
		Handler: mux,
	}

	log.Infof("WS server is listening on address: %s", l.address)
	err := l.server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (l *Listener) Close() error {
	if l.server == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	log.Debugf("closing WS server")
	if err := l.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("server shutdown failed: %v", err)
	}

	l.wg.Wait()
	return nil
}

func (l *Listener) onAccept(w http.ResponseWriter, r *http.Request) {
	l.wg.Add(1)
	defer l.wg.Done()

	wsConn, err := websocket.Accept(w, r, nil)
	if err != nil {
		log.Errorf("failed to accept ws connection: %s", err)
		return
	}

	rAddr, err := net.ResolveTCPAddr("tcp", r.RemoteAddr)
	if err != nil {
		_ = wsConn.Close(websocket.StatusInternalError, "internal error")
		return
	}

	lAddr, err := net.ResolveTCPAddr("tcp", l.server.Addr)
	if err != nil {
		_ = wsConn.Close(websocket.StatusInternalError, "internal error")
		return
	}

	conn := NewConn(wsConn, lAddr, rAddr)
	l.acceptFn(conn)
	return
}
