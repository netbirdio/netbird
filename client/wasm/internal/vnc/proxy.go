//go:build js

package vnc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall/js"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	vncProxyHost   = "vnc.proxy.local"
	vncProxyScheme = "ws"
	vncDialTimeout = 15 * time.Second

	// Connection modes matching server/server.go constants.
	modeAttach  byte = 0
	modeSession byte = 1

	// WebSocket close codes the dashboard branches on. Codes 1000-1015
	// are reserved by RFC 6455; 4000-4999 are application-defined.
	wsCodeNormal       = 1000
	wsCodeAbnormal     = 1006
	wsCodeDialTimeout  = 4001
	wsCodeDialFailure  = 4002
	wsCodeSessionSetup = 4003
	wsCodeTransport    = 4004
)

// VNCProxy bridges WebSocket connections from noVNC in the browser
// to TCP VNC server connections through the NetBird tunnel.
type VNCProxy struct {
	nbClient interface {
		Dial(ctx context.Context, network, address string) (net.Conn, error)
	}
	activeConnections map[string]*vncConnection
	destinations      map[string]vncDestination
	// pendingHandlers holds the js.Func for handleVNCWebSocket_<id> between
	// CreateProxy and handleWebSocketConnection so we can move it onto the
	// vncConnection for later release.
	pendingHandlers map[string]js.Func
	mu              sync.Mutex
	nextID          atomic.Uint64
}

type vncDestination struct {
	address   string
	mode      byte
	username  string
	jwt       string
	sessionID uint32 // Windows session ID (0 = auto/console)
	width     uint16 // Requested viewport width for session mode (0 = default)
	height    uint16 // Requested viewport height for session mode (0 = default)
}

type vncConnection struct {
	id          string
	destination vncDestination
	mu          sync.Mutex
	vncConn     net.Conn
	wsHandlers  js.Value
	ctx         context.Context
	cancel      context.CancelFunc
	// Go-side callbacks exposed to JS. js.FuncOf pins the Go closure in a
	// global handle map and MUST be released, otherwise every connection
	// leaks the Go memory the closure captures.
	wsHandlerFn js.Func
	onMessageFn js.Func
	onCloseFn   js.Func
}

// NewVNCProxy creates a new VNC proxy.
func NewVNCProxy(client interface {
	Dial(ctx context.Context, network, address string) (net.Conn, error)
}) *VNCProxy {
	return &VNCProxy{
		nbClient:          client,
		activeConnections: make(map[string]*vncConnection),
	}
}

// ProxyRequest bundles the per-call parameters for CreateProxy so the JS
// boundary doesn't drown callers in a wide positional argument list.
type ProxyRequest struct {
	Hostname  string
	Port      string
	Mode      string
	Username  string
	JWT       string
	SessionID uint32
	Width     uint16
	Height    uint16
}

// CreateProxy creates a new proxy endpoint for the given VNC destination.
// req.Mode is "attach" (capture current display) or "session" (virtual session).
// req.Username is required for session mode. req.Width/Height request the
// virtual display geometry for session mode; 0 means use the server default.
// Returns a JS Promise that resolves to the WebSocket proxy URL.
func (p *VNCProxy) CreateProxy(req ProxyRequest) js.Value {
	hostname, port, mode, username, jwt := req.Hostname, req.Port, req.Mode, req.Username, req.JWT
	sessionID, width, height := req.SessionID, req.Width, req.Height
	address := net.JoinHostPort(hostname, port)

	var m byte
	if mode == "session" {
		m = modeSession
	}

	dest := vncDestination{
		address:   address,
		mode:      m,
		username:  username,
		jwt:       jwt,
		sessionID: sessionID,
		width:     width,
		height:    height,
	}
	return p.newProxyPromise(address, mode, username, dest)
}

// newProxyPromise wraps the JS Promise creation + executor lifecycle so
// CreateProxy stays a thin parameter-bundling entrypoint.
func (p *VNCProxy) newProxyPromise(address, mode, username string, dest vncDestination) js.Value {

	var executor js.Func
	executor = js.FuncOf(func(_ js.Value, args []js.Value) any {
		resolve := args[0]

		go func() {
			defer executor.Release()

			proxyID := fmt.Sprintf("vnc_proxy_%d", p.nextID.Add(1))

			p.mu.Lock()
			if p.destinations == nil {
				p.destinations = make(map[string]vncDestination)
			}
			p.destinations[proxyID] = dest
			p.mu.Unlock()

			proxyURL := fmt.Sprintf("%s://%s/%s", vncProxyScheme, vncProxyHost, proxyID)

			handlerFn := js.FuncOf(func(_ js.Value, args []js.Value) any {
				if len(args) < 1 {
					return js.ValueOf("error: requires WebSocket argument")
				}
				p.handleWebSocketConnection(args[0], proxyID)
				return nil
			})
			p.mu.Lock()
			if p.pendingHandlers == nil {
				p.pendingHandlers = make(map[string]js.Func)
			}
			p.pendingHandlers[proxyID] = handlerFn
			p.mu.Unlock()
			js.Global().Set(fmt.Sprintf("handleVNCWebSocket_%s", proxyID), handlerFn)

			log.Infof("created VNC proxy: %s -> %s (mode=%s, user=%s)", proxyURL, address, mode, username)
			resolve.Invoke(proxyURL)
		}()

		return nil
	})
	return js.Global().Get("Promise").New(executor)
}

func (p *VNCProxy) handleWebSocketConnection(ws js.Value, proxyID string) {
	p.mu.Lock()
	dest, ok := p.destinations[proxyID]
	handlerFn := p.pendingHandlers[proxyID]
	delete(p.pendingHandlers, proxyID)
	p.mu.Unlock()

	if !ok {
		log.Errorf("no destination for VNC proxy %s", proxyID)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())

	conn := &vncConnection{
		id:          proxyID,
		destination: dest,
		wsHandlers:  ws,
		ctx:         ctx,
		cancel:      cancel,
		wsHandlerFn: handlerFn,
	}

	p.mu.Lock()
	p.activeConnections[proxyID] = conn
	p.mu.Unlock()

	p.setupWebSocketHandlers(ws, conn)
	go p.connectToVNC(conn)

	log.Infof("VNC proxy WebSocket connection established for %s", proxyID)
}

func (p *VNCProxy) setupWebSocketHandlers(ws js.Value, conn *vncConnection) {
	conn.onMessageFn = js.FuncOf(func(_ js.Value, args []js.Value) any {
		if len(args) < 1 {
			return nil
		}
		data := args[0]
		go p.handleWebSocketMessage(conn, data)
		return nil
	})
	ws.Set("onGoMessage", conn.onMessageFn)

	conn.onCloseFn = js.FuncOf(func(_ js.Value, _ []js.Value) any {
		log.Debug("VNC WebSocket closed by JavaScript")
		conn.cancel()
		return nil
	})
	ws.Set("onGoClose", conn.onCloseFn)
}

func (p *VNCProxy) handleWebSocketMessage(conn *vncConnection, data js.Value) {
	if !data.InstanceOf(js.Global().Get("Uint8Array")) {
		return
	}

	length := data.Get("length").Int()
	buf := make([]byte, length)
	js.CopyBytesToGo(buf, data)

	conn.mu.Lock()
	vncConn := conn.vncConn
	conn.mu.Unlock()

	if vncConn == nil {
		return
	}

	if _, err := vncConn.Write(buf); err != nil {
		log.Debugf("write to VNC server: %v", err)
	}
}

func (p *VNCProxy) connectToVNC(conn *vncConnection) {
	ctx, cancel := context.WithTimeout(conn.ctx, vncDialTimeout)
	defer cancel()

	vncConn, err := p.nbClient.Dial(ctx, "tcp", conn.destination.address)
	if err != nil {
		log.Errorf("VNC connect to %s: %v", conn.destination.address, err)
		// Close the WebSocket so noVNC fires a disconnect event.
		code := wsCodeDialFailure
		if errors.Is(err, context.DeadlineExceeded) {
			code = wsCodeDialTimeout
		}
		if conn.wsHandlers.Get("close").Truthy() {
			conn.wsHandlers.Call("close", code, fmt.Sprintf("connect to peer: %v", err))
		}
		p.cleanupConnection(conn)
		return
	}
	conn.mu.Lock()
	conn.vncConn = vncConn
	conn.mu.Unlock()

	// Send the NetBird VNC session header before the RFB handshake.
	if err := p.sendSessionHeader(vncConn, conn.destination); err != nil {
		log.Errorf("send VNC session header: %v", err)
		if conn.wsHandlers.Get("close").Truthy() {
			conn.wsHandlers.Call("close", wsCodeSessionSetup, fmt.Sprintf("send session header: %v", err))
		}
		p.cleanupConnection(conn)
		return
	}

	// WS→TCP is handled by the onGoMessage handler set in setupWebSocketHandlers,
	// which writes directly to the VNC connection as data arrives from JS.
	// Only the TCP→WS direction needs a read loop here.
	go p.forwardConnToWS(conn)

	<-conn.ctx.Done()
	p.cleanupConnection(conn)
}

// sendSessionHeader writes mode, username, JWT, Windows session ID, and the
// requested viewport size to the VNC server.
// Format: [mode:1] [username_len:2] [username:N] [jwt_len:2] [jwt:N]
//
//	[session_id:4] [width:2] [height:2]
func (p *VNCProxy) sendSessionHeader(conn net.Conn, dest vncDestination) error {
	usernameBytes := []byte(dest.username)
	jwtBytes := []byte(dest.jwt)
	if len(usernameBytes) > 0xFFFF {
		return fmt.Errorf("username too long: %d bytes (max %d)", len(usernameBytes), 0xFFFF)
	}
	if len(jwtBytes) > 0xFFFF {
		return fmt.Errorf("jwt too long: %d bytes (max %d)", len(jwtBytes), 0xFFFF)
	}
	hdr := make([]byte, 3+len(usernameBytes)+2+len(jwtBytes)+4+4)
	hdr[0] = dest.mode
	hdr[1] = byte(len(usernameBytes) >> 8)
	hdr[2] = byte(len(usernameBytes))
	off := 3
	copy(hdr[off:], usernameBytes)
	off += len(usernameBytes)
	hdr[off] = byte(len(jwtBytes) >> 8)
	hdr[off+1] = byte(len(jwtBytes))
	off += 2
	copy(hdr[off:], jwtBytes)
	off += len(jwtBytes)
	hdr[off] = byte(dest.sessionID >> 24)
	hdr[off+1] = byte(dest.sessionID >> 16)
	hdr[off+2] = byte(dest.sessionID >> 8)
	hdr[off+3] = byte(dest.sessionID)
	off += 4
	hdr[off] = byte(dest.width >> 8)
	hdr[off+1] = byte(dest.width)
	hdr[off+2] = byte(dest.height >> 8)
	hdr[off+3] = byte(dest.height)

	for off := 0; off < len(hdr); {
		n, err := conn.Write(hdr[off:])
		if err != nil {
			return fmt.Errorf("write session header: %w", err)
		}
		off += n
	}
	return nil
}

func (p *VNCProxy) forwardConnToWS(conn *vncConnection) {
	buf := make([]byte, 32*1024)

	for {
		if conn.ctx.Err() != nil {
			return
		}
		vc, ok := conn.snapshotVNC()
		if !ok {
			return
		}
		if err := vc.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
			log.Debugf("set VNC read deadline: %v", err)
		}
		n, err := vc.Read(buf)
		if err != nil {
			if p.handleConnReadError(conn, err) {
				return
			}
			continue
		}
		if n > 0 {
			p.sendToWebSocket(conn, buf[:n])
		}
	}
}

// snapshotVNC returns the current vncConn under conn.mu, with ok=false when
// the connection has already been cleaned up.
func (c *vncConnection) snapshotVNC() (net.Conn, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.vncConn == nil {
		return nil, false
	}
	return c.vncConn, true
}

// handleConnReadError classifies an error from the VNC read loop. Returns
// true if the caller should exit and trigger the cleanup path. A read
// timeout counts as a fatal error: in a healthy session the server emits
// empty FramebufferUpdate responses several times per second, so a full
// idleReadDeadline of silence means the peer is dead (process gone,
// machine off, network partition) and the in-browser TCP stack will
// never surface that on its own.
func (p *VNCProxy) handleConnReadError(conn *vncConnection, err error) bool {
	if conn.ctx.Err() != nil {
		return true
	}
	if netErr, ok := err.(interface{ Timeout() bool }); ok && netErr.Timeout() {
		log.Debugf("VNC read deadline expired; treating peer as dead")
	} else if err != io.EOF {
		log.Debugf("read from VNC connection: %v", err)
	}
	if conn.wsHandlers.Get("close").Truthy() {
		conn.wsHandlers.Call("close", wsCodeTransport, "VNC connection lost")
	}
	conn.cancel()
	return true
}

func (p *VNCProxy) sendToWebSocket(conn *vncConnection, data []byte) {
	if conn.wsHandlers.Get("receiveFromGo").Truthy() {
		uint8Array := js.Global().Get("Uint8Array").New(len(data))
		js.CopyBytesToJS(uint8Array, data)
		conn.wsHandlers.Call("receiveFromGo", uint8Array.Get("buffer"))
	} else if conn.wsHandlers.Get("send").Truthy() {
		uint8Array := js.Global().Get("Uint8Array").New(len(data))
		js.CopyBytesToJS(uint8Array, data)
		conn.wsHandlers.Call("send", uint8Array.Get("buffer"))
	}
}

func (p *VNCProxy) cleanupConnection(conn *vncConnection) {
	log.Debugf("cleaning up VNC connection %s", conn.id)
	conn.cancel()

	conn.mu.Lock()
	vncConn := conn.vncConn
	conn.vncConn = nil
	conn.mu.Unlock()

	if vncConn != nil {
		if err := vncConn.Close(); err != nil {
			log.Debugf("close VNC connection: %v", err)
		}
	}

	// Remove the global JS handler registered in CreateProxy.
	globalName := fmt.Sprintf("handleVNCWebSocket_%s", conn.id)
	js.Global().Delete(globalName)

	// Release all js.Func handles; js.FuncOf pins the Go closure and the
	// allocations it captures until Release is called.
	conn.wsHandlerFn.Release()
	conn.onMessageFn.Release()
	conn.onCloseFn.Release()

	p.mu.Lock()
	delete(p.activeConnections, conn.id)
	delete(p.destinations, conn.id)
	delete(p.pendingHandlers, conn.id)
	p.mu.Unlock()
}
