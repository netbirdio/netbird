package server

import (
	"bytes"
	"context"
	"net"
	"time"

	"github.com/coder/websocket"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type wsConnAdapter struct {
	prefix                  string
	ctx                     context.Context
	conn                    *websocket.Conn
	metrics                 MetricsRecorder
	clientAddr              string
	closed                  bool
	bufferedRead            []byte
	frameBuffer             *bytes.Buffer
	framer                  *http2.Framer
	headerReadDeadlineTimer *time.Timer
}

var _ net.Conn = &wsConnAdapter{}

type wsAddr struct{ prefix string }

func (wa wsAddr) Network() string { return wa.prefix + "ws-proxy" }
func (wa wsAddr) String() string  { return wa.prefix + "ws-proxy" }

func (ws *wsConnAdapter) WithFrameSnooper(d time.Duration) *wsConnAdapter {
	if d == 0 {
		return ws
	}

	ws.frameBuffer = bytes.NewBuffer(make([]byte, 0, 512))
	ws.framer = http2.NewFramer(nil, ws.frameBuffer)
	ws.framer.ReadMetaHeaders = hpack.NewDecoder(0, nil)
	ws.headerReadDeadlineTimer = time.AfterFunc(d, ws.onReadTimeout)
	return ws
}

func (ws *wsConnAdapter) Read(b []byte) (int, error) {
	if len(ws.bufferedRead) > 0 {
		return ws.readFromBuffer(b)
	}

	msgType, data, err := ws.conn.Read(ws.ctx)
	if err != nil {
		switch {
		case ws.ctx.Err() != nil:
			log.Debugf("WebSocket from %s terminating due to context cancellation", ws.clientAddr)
		case websocket.CloseStatus(err) != -1:
			log.Debugf("WebSocket from %s disconnected", ws.clientAddr)
		default:
			ws.recordError(ws.ctx, "websocket_read_error")
			log.Debugf("WebSocket read error from %s: %v", ws.clientAddr, err)
		}
		return copy(b, data), err
	}
	if msgType != websocket.MessageBinary {
		log.Warnf("Unexpected WebSocket message type from %s: %v", ws.clientAddr, msgType)
		return 0, nil
	}

	ws.bufferedRead = data
	return ws.readFromBuffer(b)
}

func (ws *wsConnAdapter) readFromBuffer(b []byte) (int, error) {
	n := copy(b, ws.bufferedRead)

	// check if we started receiving data, stop the header read timeout timer
	if ws.isFramerActive() {
		_, _ = ws.frameBuffer.Write(b) // we don't care about the number of bytes copied and no errors are returned from Write
		if frame, err := ws.framer.ReadFrame(); err != nil && frame != nil && frame.Header().Type == http2.FrameData {
			ws.headerReadDeadlineTimer.Stop()
			ws.cleanupFramer()
		}
	}

	ws.recordBytesTransferred(ws.ctx, "ws_to_grpc", n)
	if n == len(ws.bufferedRead) {
		ws.bufferedRead = nil
		return n, nil
	} else {
		ws.bufferedRead = ws.bufferedRead[n:]
	}
	return n, nil
}

func (ws *wsConnAdapter) Write(b []byte) (int, error) {
	maybeErr := ws.ctx.Err()

	n := len(b)
	if n == 0 {
		return n, maybeErr
	}
	if maybeErr != nil {
		return 0, maybeErr
	}
	if err := ws.conn.Write(ws.ctx, websocket.MessageBinary, b[:n]); err != nil {
		ws.recordError(ws.ctx, "websocket_write_error")
		log.Warnf("WebSocket write error for %s: %v", ws.clientAddr, err)
		return 0, err // we don't know how many bytes have been written
	}

	ws.recordBytesTransferred(ws.ctx, "grpc_to_ws", n)
	return n, nil
}

func (ws *wsConnAdapter) Close() error {
	ws.closed = true
	return ws.conn.Close(websocket.StatusNormalClosure, "")
}

func (ws *wsConnAdapter) LocalAddr() net.Addr  { return wsAddr{ws.prefix} }
func (ws *wsConnAdapter) RemoteAddr() net.Addr { return wsAddr{ws.prefix} }

func (ws *wsConnAdapter) SetDeadline(t time.Time) error {
	return nil
}

func (ws *wsConnAdapter) SetReadDeadline(t time.Time) error {
	return nil
}

func (ws *wsConnAdapter) SetWriteDeadline(t time.Time) error {
	return nil
}

func (ws *wsConnAdapter) recordError(ctx context.Context, errorType string) {
	if ws.metrics == nil {
		return
	}
	ws.metrics.RecordError(ctx, errorType)
}

func (ws *wsConnAdapter) recordBytesTransferred(ctx context.Context, direction string, bytes int) {
	if ws.metrics == nil {
		return
	}
	ws.metrics.RecordBytesTransferred(ctx, direction, int64(bytes))
}

func (ws *wsConnAdapter) IsClosed() bool {
	return ws.closed
}

func (ws *wsConnAdapter) onReadTimeout() {
	ws.Close()
}

func (ws *wsConnAdapter) isFramerActive() bool {
	return ws.framer != nil && ws.headerReadDeadlineTimer != nil
}

func (ws *wsConnAdapter) cleanupFramer() {
	ws.frameBuffer = nil
	ws.framer = nil
	ws.headerReadDeadlineTimer = nil
}
