//go:build js

package vnc

import (
	"context"
	crand "crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall/js"
	"time"

	"github.com/flynn/noise"
	log "github.com/sirupsen/logrus"
)

var cryptoRandRead = crand.Read

// proxyIDCounter is process-unique across every createVNCProxy call so each
// proxy/connection registers a distinct global handler name. A per-proxy
// counter would restart at 1 for every new VNCProxy, letting a reconnect's
// cleanup delete the new proxy's handler.
var proxyIDCounter atomic.Uint64

// vncIdentityMagic mirrors the server side in client/vnc/server/server.go.
var vncIdentityMagic = []byte("NBV3")

// Noise_IK_25519_ChaChaPoly_SHA256 message sizes (with empty payloads).
const (
	noiseInitiatorMsgLen = 96
	noiseResponderMsgLen = 48
)

var vncNoiseSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)

// vncNoisePrologueMagic must stay byte-identical to the server side
// (see client/vnc/server/handshake.go). Any drift here breaks every VNC
// handshake.
var vncNoisePrologueMagic = []byte("NetBird/VNC/Noise/v1\x00")

// buildVNCNoisePrologue mirrors server.BuildVNCNoisePrologue. Both sides
// hash (magic || mode || u16len(username) || username) into the
// handshake hash; a client that lies about its mode/username in the
// cleartext header prefix produces a divergent prologue, the responder
// computes the truthful prologue from what it just read, and the AEAD
// MAC over the handshake state fails to verify.
func buildVNCNoisePrologue(mode byte, username string) []byte {
	out := make([]byte, 0, len(vncNoisePrologueMagic)+1+2+len(username))
	out = append(out, vncNoisePrologueMagic...)
	out = append(out, mode)
	out = append(out, byte(len(username)>>8), byte(len(username)))
	out = append(out, []byte(username)...)
	return out
}

// sessionKeyStore retains per-session X25519 keypairs so the JS layer
// only sees an opaque session id + the public key; the private key never
// leaves wasm.
var sessionKeyStore = struct {
	mu   sync.Mutex
	keys map[string]noise.DHKey
}{keys: map[string]noise.DHKey{}}

// NewSessionKey mints an X25519 keypair, stores the private half under a
// fresh random session id, and returns (id, pubkey).
func NewSessionKey() (string, []byte, error) {
	kp, err := noise.DH25519.GenerateKeypair(nil)
	if err != nil {
		return "", nil, fmt.Errorf("generate keypair: %w", err)
	}
	idBytes := make([]byte, 16)
	if _, err := cryptoRandRead(idBytes); err != nil {
		return "", nil, fmt.Errorf("session id randomness: %w", err)
	}
	id := base64.RawURLEncoding.EncodeToString(idBytes)
	sessionKeyStore.mu.Lock()
	sessionKeyStore.keys[id] = kp
	sessionKeyStore.mu.Unlock()
	return id, kp.Public, nil
}

// lookupSessionKey returns the keypair for id. Keys stay live for the
// WASM lifetime so the same session handle can drive multiple VNC
// connections (reconnect, multiple peers, etc.). The handle is just an
// opaque map key; the private half never leaves wasm.
func lookupSessionKey(id string) (noise.DHKey, bool) {
	sessionKeyStore.mu.Lock()
	defer sessionKeyStore.mu.Unlock()
	kp, ok := sessionKeyStore.keys[id]
	return kp, ok
}

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
type vncNBClient interface {
	Dial(ctx context.Context, network, address string) (net.Conn, error)
}

type VNCProxy struct {
	nbClient          vncNBClient
	activeConnections map[string]*vncConnection
	destinations      map[string]vncDestination
	// pendingHandlers holds the js.Func for handleVNCWebSocket_<id> between
	// CreateProxy and handleWebSocketConnection so we can move it onto the
	// vncConnection for later release.
	pendingHandlers map[string]js.Func
	mu              sync.Mutex
}

type vncDestination struct {
	address     string
	mode        byte
	username    string
	sessionPriv []byte
	sessionPub  []byte
	sessionID   uint32
	width       uint16
	height      uint16
	peerPubKey  []byte
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
	// writeQueue carries inbound WS payloads to a single writer goroutine so
	// vncConn.Write calls stay serialized in arrival order.
	writeQueue  chan []byte
	cleanupOnce sync.Once
}

// NewVNCProxy creates a new VNC proxy.
func NewVNCProxy(client vncNBClient) *VNCProxy {
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
	SessionID uint32
	Width     uint16
	Height    uint16
	// PeerPublicKey is the destination peer's base64 X25519 public key,
	// used as the responder static in the Noise_IK handshake.
	PeerPublicKey string
	// KeySessionID is the handle returned by generateVNCSessionKey. The
	// matching private key is looked up inside wasm and never crosses
	// the JS boundary.
	KeySessionID string
}

// CreateProxy creates a new proxy endpoint for the given VNC destination.
// req.Mode is "attach" (capture current display) or "session" (virtual session).
// req.Username is required for session mode. req.Width/Height request the
// virtual display geometry for session mode; 0 means use the server default.
// Returns a JS Promise that resolves to the WebSocket proxy URL.
func (p *VNCProxy) CreateProxy(req ProxyRequest) js.Value {
	hostname, port, mode, username := req.Hostname, req.Port, req.Mode, req.Username
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
		sessionID: sessionID,
		width:     width,
		height:    height,
	}
	if req.KeySessionID != "" {
		kp, ok := lookupSessionKey(req.KeySessionID)
		if !ok {
			return rejectedPromise("unknown VNC session id")
		}
		dest.sessionPriv = kp.Private
		dest.sessionPub = kp.Public
		pub, err := decodePeerPubKey(req.PeerPublicKey)
		if err != nil {
			return rejectedPromise(fmt.Sprintf("invalid peer public key: %v", err))
		}
		dest.peerPubKey = pub
	}
	return p.newProxyPromise(address, mode, username, dest)
}

// decodePeerPubKey parses a base64-encoded 32-byte X25519 public key.
func decodePeerPubKey(b64 string) ([]byte, error) {
	if b64 == "" {
		return nil, errors.New("peer public key missing")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("expected 32 bytes, got %d", len(raw))
	}
	return raw, nil
}

// rejectedPromise returns a rejected Promise carrying msg as the
// reason. Callers in JS see this via `await ...` throwing.
func rejectedPromise(msg string) js.Value {
	promise := js.Global().Get("Promise")
	return promise.Call("reject", js.ValueOf(msg))
}

// newProxyPromise wraps the JS Promise creation + executor lifecycle so
// CreateProxy stays a thin parameter-bundling entrypoint.
func (p *VNCProxy) newProxyPromise(address, mode, username string, dest vncDestination) js.Value {

	var executor js.Func
	executor = js.FuncOf(func(_ js.Value, args []js.Value) any {
		resolve := args[0]

		go func() {
			defer executor.Release()

			proxyID := fmt.Sprintf("vnc_proxy_%d", proxyIDCounter.Add(1))

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
		writeQueue:  make(chan []byte, 256),
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
		p.enqueueWebSocketMessage(conn, args[0])
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

// enqueueWebSocketMessage copies an inbound WS payload into Go memory and
// hands it to the writer goroutine in arrival order. JS onmessage events are
// delivered single-threaded on the event loop, so copying here preserves
// stream order. When the queue is full the connection is torn down rather
// than dropping bytes, which would corrupt the RFB stream.
func (p *VNCProxy) enqueueWebSocketMessage(conn *vncConnection, data js.Value) {
	if !data.InstanceOf(js.Global().Get("Uint8Array")) {
		return
	}

	length := data.Get("length").Int()
	buf := make([]byte, length)
	js.CopyBytesToGo(buf, data)

	select {
	case <-conn.ctx.Done():
	case conn.writeQueue <- buf:
	default:
		log.Debugf("VNC write queue full for %s; closing connection", conn.id)
		conn.cancel()
	}
}

// writeQueueLoop drains the ordered write queue and performs the blocking
// vncConn.Write sequentially, serializing WS→TCP writes. It exits when the
// connection context is cancelled.
func (p *VNCProxy) writeQueueLoop(conn *vncConnection, vncConn net.Conn) {
	for {
		select {
		case <-conn.ctx.Done():
			return
		case buf := <-conn.writeQueue:
			if _, err := vncConn.Write(buf); err != nil {
				log.Debugf("write to VNC server: %v", err)
				conn.cancel()
				return
			}
		}
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

	// WS→TCP payloads are enqueued in arrival order by the onGoMessage handler
	// and drained sequentially by a single writer goroutine, keeping the RFB
	// stream ordered. The TCP→WS direction has its own read loop.
	go p.writeQueueLoop(conn, vncConn)
	go p.forwardConnToWS(conn)

	<-conn.ctx.Done()
	p.cleanupConnection(conn)
}

// sendSessionHeader writes the NetBird VNC connection header: mode +
// username prefix, an optional Noise_IK handshake that authenticates the
// client and the server, then the trailing sessionID / width / height
// fields the daemon needs once auth is settled.
func (p *VNCProxy) sendSessionHeader(conn net.Conn, dest vncDestination) error {
	usernameBytes := []byte(dest.username)
	if len(usernameBytes) > 0xFFFF {
		return fmt.Errorf("username too long: %d bytes (max %d)", len(usernameBytes), 0xFFFF)
	}
	prefix := make([]byte, 3+len(usernameBytes))
	prefix[0] = dest.mode
	prefix[1] = byte(len(usernameBytes) >> 8)
	prefix[2] = byte(len(usernameBytes))
	copy(prefix[3:], usernameBytes)
	if err := writeAll(conn, prefix); err != nil {
		return fmt.Errorf("write header prefix: %w", err)
	}

	if dest.sessionPriv == nil {
		return p.writeHeaderTail(conn, dest)
	}
	if err := p.runNoiseHandshake(conn, dest); err != nil {
		return fmt.Errorf("noise handshake: %w", err)
	}
	return p.writeHeaderTail(conn, dest)
}

// writeHeaderTail writes the post-auth trailing fields (sessionID,
// width, height) the daemon reads regardless of whether the Noise
// handshake was performed.
func (p *VNCProxy) writeHeaderTail(conn net.Conn, dest vncDestination) error {
	tail := make([]byte, 4+4)
	tail[0] = byte(dest.sessionID >> 24)
	tail[1] = byte(dest.sessionID >> 16)
	tail[2] = byte(dest.sessionID >> 8)
	tail[3] = byte(dest.sessionID)
	tail[4] = byte(dest.width >> 8)
	tail[5] = byte(dest.width)
	tail[6] = byte(dest.height >> 8)
	tail[7] = byte(dest.height)
	if err := writeAll(conn, tail); err != nil {
		return fmt.Errorf("write header tail: %w", err)
	}
	return nil
}

// runNoiseHandshake performs the initiator side of a Noise_IK handshake
// against the destination daemon. The session keypair authenticates the
// client; the daemon's pre-known peer pubkey authenticates the server.
func (p *VNCProxy) runNoiseHandshake(conn net.Conn, dest vncDestination) error {
	state, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   vncNoiseSuite,
		Pattern:       noise.HandshakeIK,
		Initiator:     true,
		Prologue:      buildVNCNoisePrologue(dest.mode, dest.username),
		StaticKeypair: noise.DHKey{Private: dest.sessionPriv, Public: dest.sessionPub},
		PeerStatic:    dest.peerPubKey,
	})
	if err != nil {
		return fmt.Errorf("noise initiator init: %w", err)
	}
	msg1, _, _, err := state.WriteMessage(nil, nil)
	if err != nil {
		return fmt.Errorf("noise write msg1: %w", err)
	}
	out := make([]byte, 0, len(vncIdentityMagic)+len(msg1))
	out = append(out, vncIdentityMagic...)
	out = append(out, msg1...)
	if err := writeAll(conn, out); err != nil {
		return fmt.Errorf("send noise msg1: %w", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return fmt.Errorf("set noise deadline: %w", err)
	}
	defer conn.SetReadDeadline(time.Time{}) //nolint:errcheck
	msg2 := make([]byte, noiseResponderMsgLen)
	if _, err := io.ReadFull(conn, msg2); err != nil {
		return fmt.Errorf("read noise msg2 from server: %w", err)
	}
	if _, _, _, err := state.ReadMessage(nil, msg2); err != nil {
		return fmt.Errorf("decrypt noise msg2 (peer pubkey mismatch or session revoked): %w", err)
	}
	return nil
}

func writeAll(conn net.Conn, buf []byte) error {
	for off := 0; off < len(buf); {
		n, err := conn.Write(buf[off:])
		if err != nil {
			return err
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
	conn.cleanupOnce.Do(func() {
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
		js.Global().Delete(fmt.Sprintf("handleVNCWebSocket_%s", conn.id))

		// Detach before releasing so a late WS event surfaces as a TypeError
		// instead of calling a released js.Func and panicking the runtime.
		if conn.wsHandlers.Truthy() {
			conn.wsHandlers.Set("onGoMessage", js.Undefined())
			conn.wsHandlers.Set("onGoClose", js.Undefined())
		}

		// wsHandlerFn is the zero js.Func when the pendingHandlers lookup
		// missed on a second connect.
		if conn.wsHandlerFn.Truthy() {
			conn.wsHandlerFn.Release()
		}
		if conn.onMessageFn.Truthy() {
			conn.onMessageFn.Release()
		}
		if conn.onCloseFn.Truthy() {
			conn.onCloseFn.Release()
		}

		p.mu.Lock()
		delete(p.activeConnections, conn.id)
		delete(p.destinations, conn.id)
		delete(p.pendingHandlers, conn.id)
		p.mu.Unlock()
	})
}
