package wt

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"sync"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/relay/protocol"
	relaylistener "github.com/netbirdio/netbird/relay/server/listener"
	nbRelay "github.com/netbirdio/netbird/shared/relay"
)

const (
	Proto protocol.Protocol = "wt"
	// Path is the HTTP path the browser dials with `new WebTransport("https://host/relay")`.
	Path = "/relay"
)

// Handler bridges WebTransport sessions into the relay's accept loop. It does
// not own a UDP socket — instead it exposes ServeQUICConn, which the
// ALPN-mux QUIC listener calls for connections that negotiated the "h3" ALPN.
type Handler struct {
	// TLSConfig must include the "h3" ALPN. It is used by http3 for stream
	// framing and 0-RTT handling.
	TLSConfig *tls.Config

	h3      *http3.Server
	wt      *webtransport.Server
	once    sync.Once
	initErr error
}

func New(tlsCfg *tls.Config) *Handler {
	return &Handler{TLSConfig: tlsCfg}
}

func (h *Handler) Protocol() protocol.Protocol { return Proto }

// Install wires the WebTransport HTTP handler. acceptFn receives every new
// session as a relay listener.Conn. Must be called before ServeQUICConn.
func (h *Handler) Install(acceptFn func(conn relaylistener.Conn)) error {
	h.once.Do(func() {
		mux := http.NewServeMux()

		h.h3 = &http3.Server{
			TLSConfig: h.TLSConfig,
			QUICConfig: &quic.Config{
				EnableDatagrams:   true,
				InitialPacketSize: nbRelay.QUICInitialPacketSize,
			},
			Handler: mux,
		}
		h.wt = &webtransport.Server{
			H3:          h.h3,
			CheckOrigin: func(*http.Request) bool { return true },
		}

		mux.HandleFunc(Path, func(w http.ResponseWriter, r *http.Request) {
			sess, err := h.wt.Upgrade(w, r)
			if err != nil {
				log.Warnf("WebTransport upgrade from %s failed: %v", r.RemoteAddr, err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			log.Infof("WebTransport client connected from %s", sess.RemoteAddr())
			acceptFn(NewConn(sess))
		})

		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "netbird relay: use "+Path+" for WebTransport", http.StatusNotFound)
		})
	})
	return h.initErr
}

// ServeQUICConn satisfies the quic.H3Handler interface used by the
// ALPN-multiplexing QUIC listener.
func (h *Handler) ServeQUICConn(conn *quic.Conn) error {
	if h.wt == nil {
		return fmt.Errorf("WebTransport handler not installed")
	}
	return h.wt.ServeQUICConn(conn)
}

func (h *Handler) Shutdown(ctx context.Context) error {
	if h.wt == nil {
		return nil
	}
	return h.wt.Close()
}
