package client

import (
	"context"
	"fmt"
	"net"
	"sync"
	"syscall/js"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/util/wsproxy"
)

const dialTimeout = 30 * time.Second

// websocketConn wraps a JavaScript WebSocket to implement net.Conn
type websocketConn struct {
	ws         js.Value
	remoteAddr string
	messages   chan []byte
	readBuf    []byte
	ctx        context.Context
	cancel     context.CancelFunc
	mu         sync.Mutex
}

func (c *websocketConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	if len(c.readBuf) > 0 {
		n := copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		c.mu.Unlock()
		return n, nil
	}
	c.mu.Unlock()

	select {
	case data := <-c.messages:
		n := copy(b, data)
		if n < len(data) {
			c.mu.Lock()
			c.readBuf = data[n:]
			c.mu.Unlock()
		}
		return n, nil
	case <-c.ctx.Done():
		return 0, c.ctx.Err()
	}
}

func (c *websocketConn) Write(b []byte) (int, error) {
	select {
	case <-c.ctx.Done():
		return 0, c.ctx.Err()
	default:
	}

	uint8Array := js.Global().Get("Uint8Array").New(len(b))
	js.CopyBytesToJS(uint8Array, b)
	c.ws.Call("send", uint8Array)
	return len(b), nil
}

func (c *websocketConn) Close() error {
	c.cancel()
	c.ws.Call("close")
	return nil
}

func (c *websocketConn) LocalAddr() net.Addr {
	return nil
}

func (c *websocketConn) RemoteAddr() net.Addr {
	return stringAddr(c.remoteAddr)
}
func (c *websocketConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *websocketConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *websocketConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// stringAddr is a simple net.Addr that returns a string
type stringAddr string

func (s stringAddr) Network() string { return "tcp" }
func (s stringAddr) String() string  { return string(s) }

// WithWebSocketDialer returns a gRPC dial option that uses WebSocket transport for JS/WASM environments.
func WithWebSocketDialer(tlsEnabled bool) grpc.DialOption {
	return grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
		scheme := "wss"
		if !tlsEnabled {
			scheme = "ws"
		}
		wsURL := fmt.Sprintf("%s://%s%s", scheme, addr, wsproxy.ProxyPath)

		ws := js.Global().Get("WebSocket").New(wsURL)

		connCtx, connCancel := context.WithCancel(context.Background())
		conn := &websocketConn{
			ws:         ws,
			remoteAddr: addr,
			messages:   make(chan []byte, 100),
			ctx:        connCtx,
			cancel:     connCancel,
		}

		ws.Set("binaryType", "arraybuffer")

		openCh := make(chan struct{})
		errorCh := make(chan error, 1)

		ws.Set("onopen", js.FuncOf(func(this js.Value, args []js.Value) any {
			close(openCh)
			return nil
		}))

		ws.Set("onerror", js.FuncOf(func(this js.Value, args []js.Value) any {
			select {
			case errorCh <- wsproxy.ErrConnectionFailed:
			default:
			}
			return nil
		}))

		ws.Set("onmessage", js.FuncOf(func(this js.Value, args []js.Value) any {
			event := args[0]
			data := event.Get("data")

			uint8Array := js.Global().Get("Uint8Array").New(data)
			length := uint8Array.Get("length").Int()
			bytes := make([]byte, length)
			js.CopyBytesToGo(bytes, uint8Array)

			select {
			case conn.messages <- bytes:
			default:
				log.Warnf("gRPC WebSocket message dropped for %s - buffer full", addr)
			}
			return nil
		}))

		ws.Set("onclose", js.FuncOf(func(this js.Value, args []js.Value) any {
			conn.cancel()
			return nil
		}))

		select {
		case <-openCh:
			return conn, nil
		case err := <-errorCh:
			return nil, err
		case <-ctx.Done():
			ws.Call("close")
			return nil, ctx.Err()
		case <-time.After(dialTimeout):
			ws.Call("close")
			return nil, wsproxy.ErrConnectionTimeout
		}
	})
}
