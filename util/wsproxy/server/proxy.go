package server

import (
	"context"
	"io"
	"net"
	"net/http"
	"sync"
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
	return http.HandlerFunc(p.handleWebSocket)
}

func (p *Proxy) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	p.metrics.RecordConnection(ctx)
	defer p.metrics.RecordDisconnection(ctx)

	log.Debugf("WebSocket proxy handling connection from %s, forwarding to internal gRPC handler", r.RemoteAddr)
	acceptOptions := &websocket.AcceptOptions{
		OriginPatterns: []string{"*"},
	}

	wsConn, err := websocket.Accept(w, r, acceptOptions)
	if err != nil {
		p.metrics.RecordError(ctx, "websocket_accept_failed")
		log.Errorf("WebSocket upgrade failed from %s: %v", r.RemoteAddr, err)
		return
	}
	defer func() {
		_ = wsConn.Close(websocket.StatusNormalClosure, "")
	}()

	clientConn, serverConn := net.Pipe()
	defer func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	}()

	log.Debugf("WebSocket proxy established: %s -> gRPC handler", r.RemoteAddr)

	go func() {
		(&http2.Server{}).ServeConn(serverConn, &http2.ServeConnOpts{
			Context: ctx,
			Handler: p.config.Handler,
		})
	}()

	p.proxyData(ctx, wsConn, clientConn, r.RemoteAddr)
}

func (p *Proxy) proxyData(ctx context.Context, wsConn *websocket.Conn, pipeConn net.Conn, clientAddr string) {
	proxyCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)

	go p.wsToPipe(proxyCtx, cancel, &wg, wsConn, pipeConn, clientAddr)
	go p.pipeToWS(proxyCtx, cancel, &wg, wsConn, pipeConn, clientAddr)

	wg.Wait()
}

func (p *Proxy) wsToPipe(ctx context.Context, cancel context.CancelFunc, wg *sync.WaitGroup, wsConn *websocket.Conn, pipeConn net.Conn, clientAddr string) {
	defer wg.Done()
	defer cancel()

	for {
		msgType, data, err := wsConn.Read(ctx)
		if err != nil {
			switch {
			case ctx.Err() != nil:
				log.Debugf("WebSocket from %s terminating due to context cancellation", clientAddr)
			case websocket.CloseStatus(err) != -1:
				log.Debugf("WebSocket from %s disconnected", clientAddr)
			default:
				p.metrics.RecordError(ctx, "websocket_read_error")
				log.Debugf("WebSocket read error from %s: %v", clientAddr, err)
			}
			return
		}

		if msgType != websocket.MessageBinary {
			log.Warnf("Unexpected WebSocket message type from %s: %v", clientAddr, msgType)
			continue
		}

		if err := pipeConn.SetWriteDeadline(time.Now().Add(ioTimeout)); err != nil {
			log.Debugf("Failed to set pipe write deadline: %v", err)
		}

		n, err := pipeConn.Write(data)
		if err != nil {
			p.metrics.RecordError(ctx, "pipe_write_error")
			log.Warnf("Pipe write error for %s: %v", clientAddr, err)
			return
		}

		p.metrics.RecordBytesTransferred(ctx, "ws_to_grpc", int64(n))
	}
}

func (p *Proxy) pipeToWS(ctx context.Context, cancel context.CancelFunc, wg *sync.WaitGroup, wsConn *websocket.Conn, pipeConn net.Conn, clientAddr string) {
	defer wg.Done()
	defer cancel()

	buf := make([]byte, bufferSize)
	for {
		if err := pipeConn.SetReadDeadline(time.Now().Add(ioTimeout)); err != nil {
			log.Debugf("Failed to set pipe read deadline: %v", err)
		}

		n, err := pipeConn.Read(buf)
		if err != nil {
			if err != io.EOF && ctx.Err() == nil {
				log.Debugf("Pipe read error for %s: %v", clientAddr, err)
			}
			return
		}

		if n > 0 {
			if err := wsConn.Write(ctx, websocket.MessageBinary, buf[:n]); err != nil {
				p.metrics.RecordError(ctx, "websocket_write_error")
				log.Warnf("WebSocket write error for %s: %v", clientAddr, err)
				return
			}

			p.metrics.RecordBytesTransferred(ctx, "grpc_to_ws", int64(n))
		}
	}
}
