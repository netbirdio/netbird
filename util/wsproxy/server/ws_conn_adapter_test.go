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

func TestAdapterHandlingConnectionClosures(t *testing.T) {
	var cases = []struct {
		description string
		casenum     int
	}{
		{"client-side ws connection is closed", 0},
		{"server-side ws connection is closed", 1},
		{"client-side context is cancelled", 2},
		{"server-side context is cancelled", 3},
	}

	for _, c := range cases {
		t.Run(c.description, func(t *testing.T) {
			serversock := filepath.Join("/tmp", "http-server-"+strconv.FormatInt(rand.Int64(), 10)+".sock")
			t.Cleanup(func() { os.Remove(serversock) })

			l, err := net.Listen("unix", serversock)
			assert.NoError(t, err)

			proxy := New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				buf, _ := io.ReadAll(r.Body)
				defer r.Body.Close()
				w.Write([]byte("echo: " + string(buf))) //nolint:errcheck
			}))

			handler, ok := proxy.Handler().(*proxyHandler)
			assert.True(t, ok)

			protocols := new(http.Protocols)
			protocols.SetHTTP1(true)
			protocols.SetUnencryptedHTTP2(true)
			httpServer := http.Server{
				Handler: handler,
			}
			go httpServer.Serve(l) //nolint:errcheck
			t.Cleanup(func() { httpServer.Close() })

			clientconn, _, err := websocket.Dial(context.Background(), "http://whatever", //nolint:bodyclose
				&websocket.DialOptions{HTTPClient: &http.Client{
					Transport: &http.Transport{
						DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
							return net.Dial("unix", serversock)
						},
					}}})
			assert.NoError(t, err)

			clientCtx, cancel := context.WithCancel(context.Background()) //nolint:govet
			h2client := &http.Client{
				Transport: &http2.Transport{
					AllowHTTP: true,
					DialTLSContext: func(_ context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
						return &wsConnAdapter{
							prefix: "test-client",
							ctx:    clientCtx,
							conn:   clientconn,
						}, nil
					},
				}}

			resp, err := h2client.Post("http://whatever", "text/html", strings.NewReader("g'day"))
			assert.NoError(t, err)

			body, err := io.ReadAll(resp.Body)
			defer resp.Body.Close()

			assert.NoError(t, err)
			assert.Equal(t, "echo: g'day", string(body))

			switch c.casenum {
			case 0:
				clientconn.Close(websocket.StatusNormalClosure, "")
			case 1:
				handler.conn.Load().Close()
			case 2:
				cancel()
			case 3:
				resp.Body.Close()
				h2client.CloseIdleConnections()
			}

			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				assert.True(c, handler.conn.Load().IsClosed())
			}, 3*time.Second, 100*time.Millisecond)
		}) //nolint:govet
	}
}

func TestAdapterHandlingHttpConnection_NoHeadersSent(t *testing.T) {
	t.Skip("currently disabled as it requires idle timeout to be set")

	serversock := filepath.Join("/tmp", "http-server-"+strconv.FormatInt(rand.Int64(), 10)+".sock")
	defer os.Remove(serversock)

	l, err := net.Listen("unix", serversock)
	assert.NoError(t, err)

	proxy := New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf, _ := io.ReadAll(r.Body)
		defer r.Body.Close()                    //nolint:errcheck
		w.Write([]byte("echo: " + string(buf))) //nolint:errcheck
	}))

	handler, ok := proxy.Handler().(*proxyHandler)
	assert.True(t, ok)

	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	httpServer := http.Server{
		Handler: handler,
	}
	go httpServer.Serve(l) //nolint:errcheck

	clientconn, _, err := websocket.Dial(context.Background(), "http://whatever", //nolint:bodyclose
		&websocket.DialOptions{HTTPClient: &http.Client{
			Transport: &http.Transport{
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					return net.Dial("unix", serversock)
				},
			}}})
	assert.NoError(t, err)

	h2client := &http.Client{
		Transport: &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(_ context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
				return &h2ConnectionSnooper{wrappedConn: &wsConnAdapter{
					prefix: "test-client",
					ctx:    context.Background(),
					conn:   clientconn,
				}, shouldDropFrame: func(f http2.FrameType) bool { return f == http2.FrameHeaders || f == http2.FrameData }}, nil
			},
		}}

	_, err = h2client.Post("http://whatever", "text/html", strings.NewReader("g'day"))
	assert.Error(t, err)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.True(c, handler.conn.Load().IsClosed())
	}, 3*time.Second, 100*time.Millisecond)
}

type h2ConnectionSnooper struct {
	wrappedConn     net.Conn
	shouldDropFrame func(f http2.FrameType) bool
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

	if hs.shouldDropFrame != nil && hs.shouldDropFrame(f.Header().Type) {
		return len(b), nil
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
