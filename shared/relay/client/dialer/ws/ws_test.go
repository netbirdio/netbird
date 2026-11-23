package ws

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/netbirdio/netbird/shared/alignedhb/keepalive"
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

// TestDialedConnExposesTCPKeepalive covers the aligned relay client: it dials
// WebSocket only and switches the TCP keepalive of that connection once the
// server confirms the heartbeat, so the TCP socket must be reachable.
func TestDialedConnExposesTCPKeepalive(t *testing.T) {
	if _, err := keepalive.Idle(nil); errors.Is(err, errors.ErrUnsupported) {
		t.Skip(err)
	}
	// Dial plain TCP, as mobile clients do, without the desktop routing hooks.
	t.Setenv("NB_DISABLE_CUSTOM_ROUTING", "true")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		_, _, _ = c.Read(r.Context())
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := (Dialer{}).Dial(ctx, "rel://"+srv.Listener.Addr().String(), "")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if err := keepalive.SetAligned(conn, time.Minute); err != nil {
		t.Fatalf("switch the keepalive of the relay connection: %v", err)
	}
	tcp, ok := keepalive.TCPConn(conn)
	if !ok {
		t.Fatal("no TCP socket below the relay connection")
	}
	idle, err := keepalive.Idle(tcp)
	if err != nil {
		t.Fatalf("read idle: %v", err)
	}
	if idle != 2*time.Minute {
		t.Errorf("idle = %s, want 2m0s at a 60 s period", idle)
	}
}
