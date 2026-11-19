package ws

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// BenchmarkConnWrite compares Conn.Write, which carries the write timeout, with
// the bare websocket write underneath it, over a loopback connection to a server
// that reads and discards. It runs without TLS, so the share of the timeout
// bookkeeping in a write is at its largest.
func BenchmarkConnWrite(b *testing.B) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer func() {
			_ = c.CloseNow()
		}()
		c.SetReadLimit(-1)
		for {
			_, rd, err := c.Reader(context.Background())
			if err != nil {
				return
			}
			if _, err := io.Copy(io.Discard, rd); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := (Dialer{}).Dial(dialCtx, "rel://"+srv.Listener.Addr().String(), "")
	if err != nil {
		b.Fatalf("dial: %s", err)
	}
	defer func() {
		_ = conn.Close()
	}()
	wsConn, ok := conn.(*Conn)
	if !ok {
		b.Fatal("the dialer must return a ws connection")
	}

	for _, size := range []int{100, 1400} {
		payload := make([]byte, size)

		b.Run(fmt.Sprintf("no-timeout/%d", size), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(size))
			for i := 0; i < b.N; i++ {
				if err := wsConn.Conn.Write(wsConn.ctx, websocket.MessageBinary, payload); err != nil {
					b.Fatalf("write: %s", err)
				}
			}
		})

		b.Run(fmt.Sprintf("timeout/%d", size), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(size))
			for i := 0; i < b.N; i++ {
				if _, err := conn.Write(payload); err != nil {
					b.Fatalf("write: %s", err)
				}
			}
		})
	}
}
