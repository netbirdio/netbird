package server

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/coder/websocket"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/util/wsproxy"
)

const (
	dialTimeout = 10 * time.Second
	bufferSize  = 32 * 1024
)

// Config contains the configuration for the WebSocket proxy.
type Config struct {
	LocalGRPCAddr   netip.AddrPort
	Path            string
	MetricsRecorder MetricsRecorder
}

// Proxy handles WebSocket to TCP proxying for gRPC connections.
type Proxy struct {
	config  Config
	metrics MetricsRecorder
}

// New creates a new WebSocket proxy instance with optional configuration
func New(localGRPCAddr netip.AddrPort, opts ...Option) *Proxy {
	config := Config{
		LocalGRPCAddr:   localGRPCAddr,
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

	log.Debugf("WebSocket proxy handling connection from %s, forwarding to %s", r.RemoteAddr, p.config.LocalGRPCAddr)
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
		if err := wsConn.Close(websocket.StatusNormalClosure, ""); err != nil {
			log.Debugf("Failed to close WebSocket: %v", err)
		}
	}()

	log.Debugf("WebSocket proxy attempting to connect to local gRPC at %s", p.config.LocalGRPCAddr)
	tcpConn, err := net.DialTimeout("tcp", p.config.LocalGRPCAddr.String(), dialTimeout)
	if err != nil {
		p.metrics.RecordError(ctx, "tcp_dial_failed")
		log.Warnf("Failed to connect to local gRPC server at %s: %v", p.config.LocalGRPCAddr, err)
		if err := wsConn.Close(websocket.StatusInternalError, "Backend unavailable"); err != nil {
			log.Debugf("Failed to close WebSocket after connection failure: %v", err)
		}
		return
	}
	defer func() {
		if err := tcpConn.Close(); err != nil {
			log.Debugf("Failed to close TCP connection: %v", err)
		}
	}()

	log.Debugf("WebSocket proxy established: client %s -> local gRPC %s", r.RemoteAddr, p.config.LocalGRPCAddr)

	p.proxyData(ctx, wsConn, tcpConn)
}

func (p *Proxy) proxyData(ctx context.Context, wsConn *websocket.Conn, tcpConn net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go p.wsToTCP(ctx, &wg, wsConn, tcpConn)
	go p.tcpToWS(ctx, &wg, wsConn, tcpConn)

	wg.Wait()
}

func (p *Proxy) wsToTCP(ctx context.Context, wg *sync.WaitGroup, wsConn *websocket.Conn, tcpConn net.Conn) {
	defer wg.Done()

	defer func() {
		if err := tcpConn.Close(); err != nil {
			log.Debugf("Failed to close WebSocket: %v", err)
		}
	}()

	for {
		if ctx.Err() != nil {
			return
		}

		msgType, data, err := wsConn.Read(ctx)
		if err != nil {
			if websocket.CloseStatus(err) == websocket.StatusNormalClosure {
				log.Debugf("WebSocket closed normally")
			} else {
				log.Errorf("WebSocket read error: %v", err)
			}
			return
		}

		if msgType != websocket.MessageBinary {
			log.Warnf("Unexpected WebSocket message type: %v", msgType)
			continue
		}

		if _, err := tcpConn.Write(data); err != nil {
			log.Errorf("TCP write error: %v", err)
			return
		}
	}
}

func (p *Proxy) tcpToWS(ctx context.Context, wg *sync.WaitGroup, wsConn *websocket.Conn, tcpConn net.Conn) {
	defer wg.Done()

	buf := make([]byte, bufferSize)
	for {
		if ctx.Err() != nil {
			return
		}

		n, err := tcpConn.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Errorf("TCP read error: %v", err)
			}
			return
		}

		if err := wsConn.Write(ctx, websocket.MessageBinary, buf[:n]); err != nil {
			log.Errorf("WebSocket write error: %v", err)
			return
		}
	}
}
