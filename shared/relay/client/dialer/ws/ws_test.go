package ws

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrepareURL(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "rel scheme with non-standard port",
			input: "rel://test-domain-2:45678",
			want:  "ws://test-domain-2:45678/relay",
		},
		{
			name:  "rels scheme with non-standard port",
			input: "rels://test-domain-2:45678",
			want:  "wss://test-domain-2:45678/relay",
		},
		{
			name:  "rel scheme without port",
			input: "rel://test-domain-2",
			want:  "ws://test-domain-2/relay",
		},
		{
			name:  "rels scheme without port",
			input: "rels://test-domain-2",
			want:  "wss://test-domain-2/relay",
		},
		{
			name:  "rel scheme with IP and port",
			input: "rel://1.2.3.4:45678",
			want:  "ws://1.2.3.4:45678/relay",
		},
		{
			name:  "rel scheme with hostname starting with rel",
			input: "rel://relay.example.com:45678",
			want:  "ws://relay.example.com:45678/relay",
		},
		{
			name:  "rel scheme with IPv6 and port",
			input: "rel://[2001:db8::1]:45678",
			want:  "ws://[2001:db8::1]:45678/relay",
		},
		{
			name:  "rels scheme with IPv6 loopback and port",
			input: "rels://[::1]:45678",
			want:  "wss://[::1]:45678/relay",
		},
		{
			name:    "unsupported scheme",
			input:   "http://test-domain-2:45678",
			wantErr: true,
		},
		{
			name:    "no scheme",
			input:   "test-domain-2:45678",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := prepareURL(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("prepareURL(%q) err = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("prepareURL(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestRequestHost(t *testing.T) {
	tests := []struct {
		name       string
		wsURL      string
		serverName string
		want       string
	}{
		{
			name:  "no server name keeps the URL host",
			wsURL: "wss://1.2.3.4:443/relay",
			want:  "",
		},
		{
			name:       "IP with port",
			wsURL:      "wss://1.2.3.4:443/relay",
			serverName: "relay.example.com",
			want:       "relay.example.com:443",
		},
		{
			name:       "IP with non-standard port",
			wsURL:      "ws://1.2.3.4:45678/relay",
			serverName: "relay.example.com",
			want:       "relay.example.com:45678",
		},
		{
			name:       "IP without port",
			wsURL:      "wss://1.2.3.4/relay",
			serverName: "relay.example.com",
			want:       "relay.example.com",
		},
		{
			name:       "IPv6 with port",
			wsURL:      "wss://[2001:db8::1]:443/relay",
			serverName: "relay.example.com",
			want:       "relay.example.com:443",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := requestHost(tt.wsURL, tt.serverName)
			if err != nil {
				t.Fatalf("requestHost(%q, %q) err = %v", tt.wsURL, tt.serverName, err)
			}
			if got != tt.want {
				t.Errorf("requestHost(%q, %q) = %q, want %q", tt.wsURL, tt.serverName, got, tt.want)
			}
		})
	}
}

func TestDialByIPSendsServerNameAsHost(t *testing.T) {
	hosts := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hosts <- r.Host
		http.NotFound(w, r)
	}))
	defer srv.Close()

	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		serverName string
		want       string
	}{
		{name: "dial by IP with server name", serverName: "relay.example.com", want: "relay.example.com:" + port},
		{name: "dial without server name", want: "127.0.0.1:" + port},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			if _, err := (Dialer{}).Dial(ctx, "rel://127.0.0.1:"+port, tt.serverName); err == nil {
				t.Fatal("expected the handshake to fail against a plain HTTP server")
			}

			select {
			case got := <-hosts:
				if got != tt.want {
					t.Errorf("server saw Host %q, want %q", got, tt.want)
				}
			case <-ctx.Done():
				t.Fatal("server never received the handshake request")
			}
		})
	}
}

func TestWriteTimesOutWhenPeerStopsReading(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		// The server never reads, so the client's writes back up in the TCP
		// buffers until one of them blocks.
		<-release
		_ = c.CloseNow()
	}))
	t.Cleanup(func() {
		close(release)
		srv.Close()
	})

	dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := (Dialer{}).Dial(dialCtx, "rel://"+srv.Listener.Addr().String(), "")
	require.NoError(t, err, "dial the server that never reads")
	t.Cleanup(func() {
		_ = conn.Close()
	})

	wsConn, ok := conn.(*Conn)
	require.True(t, ok, "the dialer must return a ws connection")
	wsConn.writeTimeout = 200 * time.Millisecond

	writeErr := make(chan error, 1)
	go func() {
		payload := make([]byte, 64*1024)
		for {
			if _, err := conn.Write(payload); err != nil {
				writeErr <- err
				return
			}
		}
	}()

	select {
	case err := <-writeErr:
		assert.ErrorIs(t, err, os.ErrDeadlineExceeded, "a blocked write must end with the write timeout")
	case <-time.After(10 * time.Second):
		t.Fatal("write did not return although the peer stopped reading")
	}

	_, err = conn.Write([]byte("x"))
	assert.ErrorIs(t, err, net.ErrClosed, "the connection must be closed once a write has timed out")
}
