package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func TestXxx(t *testing.T) {
	var cases = []struct {
		description      string
		casenum          int
		frameHandlerFunc func(b []byte) (n int, err error)
	}{
		// {"client-side ws connection is closed", 0, nil},
		// {"server-side ws connection is closed", 1, nil},
		// {"client-side context is cancelled", 2, nil},
		// {"server-side context is cancelled", 3, nil},
		{"client slow to start a stream", 4, func(b []byte) (n int, err error) { return len(b), nil }},
	}

	for _, c := range cases {
		t.Run(c.description, func(t *testing.T) {
			serversock := filepath.Join("/tmp", "http-server-"+strconv.FormatInt(rand.Int64(), 10)+".sock")
			defer os.Remove(serversock)

			l, err := net.Listen("unix", serversock)
			assert.NoError(t, err)

			proxy := New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				buf, _ := io.ReadAll(r.Body)
				defer r.Body.Close()
				w.Write([]byte("echo: " + string(buf)))
			}))

			handler, ok := proxy.Handler().(*proxyHandler)
			assert.True(t, ok)

			protocols := new(http.Protocols)
			protocols.SetHTTP1(true)
			protocols.SetUnencryptedHTTP2(true)
			httpServer := http.Server{
				Handler:     handler,
				IdleTimeout: 3 * time.Second,
				// Handler: h2c.NewHandler(handler, &http2.Server{
				// 	IdleTimeout: 500 * time.Millisecond,
				// }),
			}
			go httpServer.Serve(l)

			clientconn, _, err := websocket.Dial(context.Background(), "http://whatever", &websocket.DialOptions{HTTPClient: &http.Client{
				Transport: &http.Transport{
					DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
						return net.Dial("unix", serversock)
					},
				}}})
			assert.NoError(t, err)

			clientCtx, cancel := context.WithCancel(context.Background())
			h2client := &http.Client{
				Transport: &http2.Transport{
					AllowHTTP: true,
					DialTLSContext: func(_ context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
						return &h2ConnectionSnooper{wrappedConn: &wsConnAdapter{
							prefix: "test-client",
							ctx:    clientCtx,
							conn:   clientconn,
						}, frameHandlerFunc: c.frameHandlerFunc}, nil
					},
				}}

			resp, err := h2client.Post("http://whatever", "text/html", strings.NewReader("g'day"))
			assert.NoError(t, err)

			body, err := io.ReadAll(resp.Body)

			assert.NoError(t, err)
			assert.Equal(t, "echo: g'day", string(body))

			switch c.casenum {
			case 0:
				clientconn.Close(websocket.StatusNormalClosure, "")
			case 1:
				handler.conn.Close()
			case 2:
				cancel()
			case 3:
				resp.Body.Close()
				h2client.CloseIdleConnections()
			}

			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				assert.True(c, handler.conn.IsClosed())
			}, 5*time.Second, 100*time.Millisecond)
		})
	}
}

type h2ConnectionSnooper struct {
	wrappedConn      net.Conn
	frameHandlerFunc func(b []byte) (n int, err error)
}

func (hs *h2ConnectionSnooper) Read(b []byte) (n int, err error) {
	return hs.wrappedConn.Read(b)
}

func (hs *h2ConnectionSnooper) Write(b []byte) (n int, err error) {
	fr := http2.NewFramer(nil, bytes.NewReader(b))
	fr.ReadMetaHeaders = hpack.NewDecoder(0, nil)
	f, err := fr.ReadFrame()
	if err != nil {
		return hs.wrappedConn.Write(b)
	}

	if (f.Header().Type == http2.FrameData || f.Header().Type == http2.FrameHeaders) && hs.frameHandlerFunc != nil {
		return hs.frameHandlerFunc(b)
	}

	return hs.wrappedConn.Write(b)
}

func (hs *h2ConnectionSnooper) Close() error { return hs.wrappedConn.Close() }

func (hs *h2ConnectionSnooper) LocalAddr() net.Addr { return hs.wrappedConn.LocalAddr() }

func (hs *h2ConnectionSnooper) RemoteAddr() net.Addr { return hs.wrappedConn.RemoteAddr() }

func (hs *h2ConnectionSnooper) SetDeadline(t time.Time) error { return hs.wrappedConn.SetDeadline(t) }

func (hs *h2ConnectionSnooper) SetReadDeadline(t time.Time) error {
	return hs.wrappedConn.SetReadDeadline(t)
}

func (hs *h2ConnectionSnooper) SetWriteDeadline(t time.Time) error {
	return hs.wrappedConn.SetWriteDeadline(t)
}
