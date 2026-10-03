package ws

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/coder/websocket"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/relay/protocol"
	relaylistener "github.com/netbirdio/netbird/relay/server/listener"
	"github.com/netbirdio/netbird/shared/relay"
	"github.com/netbirdio/netbird/trustedproxy"
)

const (
	Proto   protocol.Protocol = "ws"
	URLPath                   = relay.WebSocketURLPath
)

type Listener struct {
	// Address is the address to listen on.
	Address string
	// TLSConfig is the TLS configuration for the server.
	TLSConfig *tls.Config
	// TrustedProxies is the set of upstream proxies whose X-Real-Ip/X-Real-Port
	// headers are trusted. Headers from any other immediate peer are ignored.
	TrustedProxies *trustedproxy.List

	listener net.Listener
	server   *http.Server
	acceptFn func(conn relaylistener.Conn)
}

func (l *Listener) Bind() error {
	listener, err := net.Listen("tcp", l.Address)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc(URLPath, l.onAccept)

	l.listener = listener
	l.server = &http.Server{
		Handler:           mux,
		TLSConfig:         l.TLSConfig,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Infof("WS server listening address: %s", l.Address)
	return nil
}

func (l *Listener) Serve(acceptFn func(conn relaylistener.Conn)) error {
	if l.listener == nil {
		return errors.New("listener is not bound")
	}

	l.acceptFn = acceptFn
	var err error
	if l.TLSConfig != nil {
		err = l.server.ServeTLS(l.listener, "", "")
	} else {
		err = l.server.Serve(l.listener)
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (l *Listener) Protocol() protocol.Protocol {
	return Proto
}

func (l *Listener) Shutdown(ctx context.Context) error {
	if l.listener == nil {
		return nil
	}

	log.Infof("stop WS listener")
	if err := l.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("server shutdown failed: %v", err)
	}
	if err := l.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("close listener: %w", err)
	}
	log.Infof("WS listener stopped")
	return nil
}

func (l *Listener) onAccept(w http.ResponseWriter, r *http.Request) {
	connRemoteAddr := remoteAddr(r, l.TrustedProxies)

	acceptOptions := &websocket.AcceptOptions{
		OriginPatterns: []string{"*"},
	}

	wsConn, err := websocket.Accept(w, r, acceptOptions)
	if err != nil {
		log.Errorf("failed to accept ws connection from %s: %s", connRemoteAddr, err)
		return
	}

	rAddr, err := net.ResolveTCPAddr("tcp", connRemoteAddr)
	if err != nil {
		err = wsConn.Close(websocket.StatusInternalError, "internal error")
		if err != nil {
			log.Errorf("failed to close ws connection: %s", err)
		}
		return
	}

	log.Infof("WS client connected from: %s", rAddr)

	conn := NewConn(wsConn, rAddr)
	l.acceptFn(conn)
}

func remoteAddr(r *http.Request, trustedProxies *trustedproxy.List) string {
	realIP := r.Header.Get("X-Real-Ip")
	realPort := r.Header.Get("X-Real-Port")
	if realIP == "" || realPort == "" {
		return r.RemoteAddr
	}

	if !trustedProxies.IsTrusted(r.RemoteAddr) {
		log.Debugf("ignoring X-Real-Ip header from untrusted peer %s", r.RemoteAddr)
		return r.RemoteAddr
	}

	return net.JoinHostPort(realIP, realPort)
}
