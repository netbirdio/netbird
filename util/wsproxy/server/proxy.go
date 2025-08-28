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
	LocalGRPCAddr netip.AddrPort
	Path          string
}

// Proxy handles WebSocket to TCP proxying for gRPC connections.
type Proxy struct {
	config Config
}

// New creates a new WebSocket proxy instance.
func New(localGRPCAddr netip.AddrPort) *Proxy {
	return &Proxy{
		config: Config{
			LocalGRPCAddr: localGRPCAddr,
			Path:          wsproxy.ProxyPath,
		},
	}
}

// Handler returns an http.Handler that proxies WebSocket connections to the local gRPC server.
func (p *Proxy) Handler() http.Handler {
	return http.HandlerFunc(p.handleWebSocket)
}

func (p *Proxy) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	log.Infof("WebSocket proxy handling connection from %s, forwarding to %s", r.RemoteAddr, p.config.LocalGRPCAddr)
	acceptOptions := &websocket.AcceptOptions{
		OriginPatterns: []string{"*"},
	}

	wsConn, err := websocket.Accept(w, r, acceptOptions)
	if err != nil {
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
		log.Warnf("Failed to connect to local gRPC server at %s: %v", p.config.LocalGRPCAddr, err)
		if err := wsConn.Close(websocket.StatusInternalError, "Backend unavailable"); err != nil {
			log.Debugf("Failed to close WebSocket: %v", err)
		}
		return
	}
	defer func() {
		if err := tcpConn.Close(); err != nil {
			log.Debugf("Failed to close WebSocket: %v", err)
		}
	}()

	log.Infof("WebSocket proxy established: client %s -> local gRPC %s", r.RemoteAddr, p.config.LocalGRPCAddr)

	ctx := r.Context()
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
		log.Tracef("Forwarded %d bytes from WebSocket to TCP", len(data))
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
		log.Tracef("Forwarded %d bytes from TCP to WebSocket", n)
	}
}
