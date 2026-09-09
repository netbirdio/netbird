package server

import (
	"net/http"
	"time"

	"github.com/coder/websocket"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/http2"

	"github.com/netbirdio/netbird/util/wsproxy"
)

const (
	bufferSize = 32 * 1024
	ioTimeout  = 5 * time.Second
)

// Config contains the configuration for the WebSocket proxy.
type Config struct {
	Handler         http.Handler
	Path            string
	MetricsRecorder MetricsRecorder
}

// Proxy handles WebSocket to gRPC handler proxying.
type Proxy struct {
	config  Config
	metrics MetricsRecorder
}

// New creates a new WebSocket proxy instance with optional configuration
func New(handler http.Handler, opts ...Option) *Proxy {
	config := Config{
		Handler:         handler,
		Path:            wsproxy.ProxyPath,
		MetricsRecorder: NoOpMetricsRecorder{}, // Default to no-op
	}

	for _, opt := range opts {
		opt(&config)
	}

	return &Proxy{
		config:  config,
		metrics: config.MetricsRecorder,
	}
}

// Handler returns an http.Handler that proxies WebSocket connections to the local gRPC server.
func (p *Proxy) Handler() http.Handler {
	return &proxyHandler{
		metrics: p.config.MetricsRecorder,
		handler: p.config.Handler,
	}
}

type proxyHandler struct {
	metrics            MetricsRecorder
	handler            http.Handler
	conn               *wsConnAdapter
	headersReadTimeout time.Duration
}

func (ph *proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	ph.metrics.RecordConnection(ctx)
	defer ph.metrics.RecordDisconnection(ctx)

	log.Debugf("WebSocket proxy handling connection from %s, forwarding to internal gRPC handler", r.RemoteAddr)
	acceptOptions := &websocket.AcceptOptions{
		OriginPatterns: []string{"*"},
	}

	wsConn, err := websocket.Accept(w, r, acceptOptions)
	if err != nil {
		ph.metrics.RecordError(ctx, "websocket_accept_failed")
		log.Errorf("WebSocket upgrade failed from %s: %v", r.RemoteAddr, err)
		return
	}
	serverConn := (&wsConnAdapter{
		ctx:        ctx,
		conn:       wsConn,
		metrics:    ph.metrics,
		clientAddr: r.RemoteAddr,
	}).WithFrameSnooper(ph.headersReadTimeout)

	defer func() {
		_ = serverConn.Close()
	}()

	ph.conn = serverConn // used in tests only

	log.Debugf("WebSocket proxy established: %s -> gRPC handler", r.RemoteAddr)

	(&http2.Server{
		// TODO (dmitri) we should limit the number of concurrent streams per connection (peer)
		// and idle timeouts
		// MaxConcurrentStreams: 20,
		// IdleTimeout: 60 * time.Second,
	}).ServeConn(serverConn, &http2.ServeConnOpts{
		Context:    ctx,
		Handler:    ph.handler,
		BaseConfig: &http.Server{
			// we don't set read/write timeouts here,
			// as they interfere with streaming grpc calls
		},
	})

	log.Debugf("WebSocket proxy closing: %s -> gRPC handler", r.RemoteAddr)
}
