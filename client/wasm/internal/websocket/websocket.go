//go:build js

package websocket

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"syscall/js"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	netbird "github.com/netbirdio/netbird/client/embed"
	log "github.com/sirupsen/logrus"
)

type closeError struct {
	code   uint16
	reason string
}

func (e *closeError) Error() string {
	return fmt.Sprintf("websocket closed: %d %s", e.code, e.reason)
}

// bufferedConn fronts a net.Conn with a reader that serves any bytes buffered
// during the WebSocket handshake before falling through to the raw conn.
type bufferedConn struct {
	net.Conn
	r io.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// Conn wraps a WebSocket connection over a NetBird TCP connection.
type Conn struct {
	conn      net.Conn
	mu        sync.Mutex
	closed    chan struct{}
	closeOnce sync.Once
	closeErr  error
}

// Dial establishes a WebSocket connection to the given URL through the NetBird network.
// Optional protocols are sent via the Sec-WebSocket-Protocol header.
func Dial(ctx context.Context, client *netbird.Client, rawURL string, protocols []string) (*Conn, error) {
	d := ws.Dialer{
		NetDial:   client.Dial,
		Protocols: protocols,
	}

	conn, br, _, err := d.Dial(ctx, rawURL)
	if err != nil {
		return nil, fmt.Errorf("websocket dial: %w", err)
	}

	// br is non-nil when the server pushed frames alongside the handshake
	// response; those bytes live in the bufio.Reader and must be drained
	// before reading from conn, otherwise we'd skip the first frames.
	if br != nil {
		if br.Buffered() > 0 {
			conn = &bufferedConn{Conn: conn, r: io.MultiReader(br, conn)}
		} else {
			ws.PutReader(br)
		}
	}

	return &Conn{
		conn:   conn,
		closed: make(chan struct{}),
	}, nil
}

// ReadMessage reads the next WebSocket message, handling control frames automatically.
func (c *Conn) ReadMessage() (ws.OpCode, []byte, error) {
	for {
		msgs, err := wsutil.ReadServerMessage(c.conn, nil)
		if err != nil {
			return 0, nil, err
		}

		for _, msg := range msgs {
			if msg.OpCode.IsControl() {
				if err := c.handleControl(msg); err != nil {
					return 0, nil, err
				}
				continue
			}
			return msg.OpCode, msg.Payload, nil
		}
	}
}

func (c *Conn) handleControl(msg wsutil.Message) error {
	switch msg.OpCode {
	case ws.OpPing:
		c.mu.Lock()
		defer c.mu.Unlock()
		return wsutil.WriteClientMessage(c.conn, ws.OpPong, msg.Payload)
	case ws.OpClose:
		code, reason := parseClosePayload(msg.Payload)
		return &closeError{code: code, reason: reason}
	default:
		return nil
	}
}

// WriteText sends a text WebSocket message.
func (c *Conn) WriteText(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return wsutil.WriteClientMessage(c.conn, ws.OpText, data)
}

// WriteBinary sends a binary WebSocket message.
func (c *Conn) WriteBinary(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return wsutil.WriteClientMessage(c.conn, ws.OpBinary, data)
}

// Close sends a close frame with StatusNormalClosure and closes the underlying connection.
func (c *Conn) Close() error {
	return c.closeWith(ws.StatusNormalClosure, "")
}

// closeWith sends a close frame with the given code/reason and closes the underlying connection.
// Used to echo the server's code when responding to a server-initiated close per RFC 6455 §5.5.1.
func (c *Conn) closeWith(code ws.StatusCode, reason string) error {
	var first bool
	c.closeOnce.Do(func() {
		first = true
		close(c.closed)

		c.mu.Lock()
		_ = wsutil.WriteClientMessage(c.conn, ws.OpClose, ws.NewCloseFrameBody(code, reason))
		c.mu.Unlock()

		c.closeErr = c.conn.Close()
	})

	if !first {
		return net.ErrClosed
	}
	return c.closeErr
}

// NewJSInterface creates a JavaScript object wrapping the WebSocket connection.
// It exposes: send(string|Uint8Array), close(), and callback properties
// onmessage, onclose, onerror.
//
// Callback properties may be set from the JS thread while the read loop
// goroutine reads them. In WASM this is safe because Go and JS share a
// single thread, but the design would need synchronization on
// multi-threaded runtimes.
func NewJSInterface(conn *Conn) js.Value {
	obj := js.Global().Get("Object").Call("create", js.Null())

	sendFunc := js.FuncOf(func(_ js.Value, args []js.Value) any {
		if len(args) < 1 {
			log.Errorf("websocket send requires a data argument")
			return js.ValueOf(false)
		}

		data := args[0]
		switch data.Type() {
		case js.TypeString:
			if err := conn.WriteText([]byte(data.String())); err != nil {
				log.Errorf("failed to send websocket text: %v", err)
				return js.ValueOf(false)
			}
		default:
			buf, err := jsToBytes(data)
			if err != nil {
				log.Errorf("failed to convert js value to bytes: %v", err)
				return js.ValueOf(false)
			}
			if err := conn.WriteBinary(buf); err != nil {
				log.Errorf("failed to send websocket binary: %v", err)
				return js.ValueOf(false)
			}
		}
		return js.ValueOf(true)
	})
	obj.Set("send", sendFunc)

	closeFunc := js.FuncOf(func(_ js.Value, _ []js.Value) any {
		if err := conn.Close(); err != nil {
			log.Debugf("failed to close websocket: %v", err)
		}
		return js.Undefined()
	})
	obj.Set("close", closeFunc)

	go func() {
		defer func() {
			if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				log.Debugf("close websocket on readLoop exit: %v", err)
			}
		}()
		readLoop(conn, obj)
		// Undefining before Release turns post-close JS calls into TypeError
		// instead of a silent "call to released function".
		obj.Set("send", js.Undefined())
		obj.Set("close", js.Undefined())
		sendFunc.Release()
		closeFunc.Release()
	}()

	return obj
}

func jsToBytes(data js.Value) ([]byte, error) {
	var uint8Array js.Value
	switch {
	case data.InstanceOf(js.Global().Get("Uint8Array")):
		uint8Array = data
	case data.InstanceOf(js.Global().Get("ArrayBuffer")):
		uint8Array = js.Global().Get("Uint8Array").New(data)
	default:
		return nil, fmt.Errorf("send: unsupported data type, use string, Uint8Array, or ArrayBuffer")
	}

	buf := make([]byte, uint8Array.Get("length").Int())
	js.CopyBytesToGo(buf, uint8Array)
	return buf, nil
}

func readLoop(conn *Conn, obj js.Value) {
	var ce *closeError
	defer func() { invokeOnClose(obj, ce) }()

	for {
		select {
		case <-conn.closed:
			return
		default:
		}

		op, payload, err := conn.ReadMessage()
		if err != nil {
			ce = handleReadError(conn, obj, err)
			return
		}

		dispatchMessage(obj, op, payload)
	}
}

func handleReadError(conn *Conn, obj js.Value, err error) *closeError {
	var ce *closeError
	if errors.As(err, &ce) {
		if cerr := conn.closeWith(ws.StatusCode(ce.code), ce.reason); cerr != nil {
			log.Debugf("failed to close websocket after server close frame: %v", cerr)
		}
		return ce
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	if onerror := obj.Get("onerror"); onerror.Truthy() {
		onerror.Invoke(js.ValueOf(err.Error()))
	}
	return nil
}

func invokeOnClose(obj js.Value, ce *closeError) {
	onclose := obj.Get("onclose")
	if !onclose.Truthy() {
		return
	}
	if ce != nil {
		onclose.Invoke(js.ValueOf(int(ce.code)), js.ValueOf(ce.reason))
		return
	}
	onclose.Invoke()
}

func dispatchMessage(obj js.Value, op ws.OpCode, payload []byte) {
	onmessage := obj.Get("onmessage")
	if !onmessage.Truthy() {
		return
	}
	switch op {
	case ws.OpText:
		onmessage.Invoke(js.ValueOf(string(payload)))
	case ws.OpBinary:
		uint8Array := js.Global().Get("Uint8Array").New(len(payload))
		js.CopyBytesToJS(uint8Array, payload)
		onmessage.Invoke(uint8Array)
	}
}

func parseClosePayload(payload []byte) (uint16, string) {
	if len(payload) < 2 {
		return 1005, "" // RFC 6455: No Status Rcvd
	}
	code := binary.BigEndian.Uint16(payload[:2])
	return code, string(payload[2:])
}
