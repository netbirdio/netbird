package client

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"go.opentelemetry.io/otel"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/relay/server"
	"github.com/netbirdio/netbird/shared/relay/auth/allow"
)

// TestClient_ServerIPRecoversFromUnresolvableFQDN verifies that when the
// primary FQDN-based dial fails (unresolvable .invalid host), Connect
// recovers via the server IP and SNI still uses the FQDN.
func TestClient_ServerIPRecoversFromUnresolvableFQDN(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	listenAddr, port := freeAddr(t)
	srvCfg := server.Config{
		Meter:          otel.Meter(""),
		ExposedAddress: fmt.Sprintf("rel://test-unresolvable-host.invalid:%d", port),
		TLSSupport:     false,
		AuthValidator:  &allow.Auth{},
	}
	srv, err := server.NewServer(srvCfg)
	if err != nil {
		t.Fatalf("create server: %s", err)
	}

	errChan := make(chan error, 1)
	go func() {
		if err := srv.Listen(server.ListenerConfig{Address: listenAddr}); err != nil {
			errChan <- err
		}
	}()
	t.Cleanup(func() {
		if err := srv.Shutdown(context.Background()); err != nil {
			t.Errorf("shutdown server: %s", err)
		}
	})
	if err := waitForServerToStart(errChan); err != nil {
		t.Fatalf("server failed to start: %s", err)
	}

	t.Run("no server IP, primary fails", func(t *testing.T) {
		c := NewClient(srvCfg.ExposedAddress, hmacTokenStore, "alice-noip", iface.DefaultMTU)
		err := c.Connect(ctx)
		if err == nil {
			_ = c.Close()
			t.Fatalf("expected connect to fail without server IP, got nil")
		}
	})

	t.Run("server IP recovers", func(t *testing.T) {
		c := NewClientWithServerIP(srvCfg.ExposedAddress, netip.MustParseAddr("127.0.0.1"), hmacTokenStore, "alice-with-ip", iface.DefaultMTU)
		if err := c.Connect(ctx); err != nil {
			t.Fatalf("connect with server IP: %s", err)
		}
		t.Cleanup(func() { _ = c.Close() })

		if !c.Ready() {
			t.Fatalf("client not ready after connect")
		}
		if got := c.ConnectedIP(); got.String() != "127.0.0.1" {
			t.Fatalf("ConnectedIP = %q, want 127.0.0.1", got)
		}
	})
}

// TestClient_ConnectedIPAfterFQDNDial verifies ConnectedIP returns the
// resolved IP after a successful FQDN-based dial. The underlying socket's
// RemoteAddr must be exposed through the dialer wrappers; if it returns
// the dial-time URL instead, ConnectedIP returns empty and the dial
// IP we advertise to peers is empty too.
func TestClient_ConnectedIPAfterFQDNDial(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	listenAddr, port := freeAddr(t)
	srvCfg := server.Config{
		Meter:          otel.Meter(""),
		ExposedAddress: fmt.Sprintf("rel://localhost:%d", port),
		TLSSupport:     false,
		AuthValidator:  &allow.Auth{},
	}
	srv, err := server.NewServer(srvCfg)
	if err != nil {
		t.Fatalf("create server: %s", err)
	}
	errChan := make(chan error, 1)
	go func() {
		if err := srv.Listen(server.ListenerConfig{Address: listenAddr}); err != nil {
			errChan <- err
		}
	}()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	if err := waitForServerToStart(errChan); err != nil {
		t.Fatalf("server failed to start: %s", err)
	}

	c := NewClient(srvCfg.ExposedAddress, hmacTokenStore, "alice-fqdn", iface.DefaultMTU)
	if err := c.Connect(ctx); err != nil {
		t.Fatalf("connect: %s", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	got := c.ConnectedIP().String()
	if got != "127.0.0.1" && got != "::1" {
		t.Fatalf("ConnectedIP after FQDN dial = %q, want 127.0.0.1 or ::1", got)
	}
}

func TestSubstituteHost(t *testing.T) {
	tests := []struct {
		name           string
		serverURL      string
		ip             string
		wantURL        string
		wantServerName string
		wantErr        bool
	}{
		{
			name:           "rels with port",
			serverURL:      "rels://relay.netbird.io:443",
			ip:             "10.0.0.5",
			wantURL:        "rels://10.0.0.5:443",
			wantServerName: "relay.netbird.io",
		},
		{
			name:           "rel with port",
			serverURL:      "rel://relay.example.com:80",
			ip:             "192.0.2.1",
			wantURL:        "rel://192.0.2.1:80",
			wantServerName: "relay.example.com",
		},
		{
			name:           "ipv6 server IP bracketed",
			serverURL:      "rels://relay.example.com:443",
			ip:             "2001:db8::1",
			wantURL:        "rels://[2001:db8::1]:443",
			wantServerName: "relay.example.com",
		},
		{
			name:           "no port",
			serverURL:      "rels://relay.example.com",
			ip:             "10.0.0.5",
			wantURL:        "rels://10.0.0.5",
			wantServerName: "relay.example.com",
		},
		{
			name:           "ipv6 server with port returns empty SNI",
			serverURL:      "rels://[2001:db8::5]:443",
			ip:             "10.0.0.5",
			wantURL:        "rels://10.0.0.5:443",
			wantServerName: "",
		},
		{
			name:           "ipv4 server with port returns empty SNI",
			serverURL:      "rels://10.0.0.5:443",
			ip:             "10.0.0.6",
			wantURL:        "rels://10.0.0.6:443",
			wantServerName: "",
		},
		{
			name:           "ipv6 server IP no port",
			serverURL:      "rels://relay.example.com",
			ip:             "2001:db8::1",
			wantURL:        "rels://[2001:db8::1]",
			wantServerName: "relay.example.com",
		},
		{
			name:      "missing scheme",
			serverURL: "relay.example.com:443",
			ip:        "10.0.0.5",
			wantErr:   true,
		},
		{
			name:      "empty",
			serverURL: "",
			ip:        "10.0.0.5",
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ip netip.Addr
			if tt.ip != "" {
				ip = netip.MustParseAddr(tt.ip)
			}
			gotURL, gotName, err := substituteHost(tt.serverURL, ip)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
			if gotURL != tt.wantURL {
				t.Errorf("URL = %q, want %q", gotURL, tt.wantURL)
			}
			if gotName != tt.wantServerName {
				t.Errorf("ServerName = %q, want %q", gotName, tt.wantServerName)
			}
		})
	}
}

func TestClient_ConnectedIPEmptyWhenNotConnected(t *testing.T) {
	c := NewClient("rel://example.invalid:80", hmacTokenStore, "x", iface.DefaultMTU)
	if got := c.ConnectedIP(); got.IsValid() {
		t.Fatalf("ConnectedIP on disconnected client = %q, want zero", got)
	}
}

// staticAddr is a net.Addr that returns a fixed string. Used to verify
// ConnectedIP parses RemoteAddr correctly.
type staticAddr struct{ s string }

func (a staticAddr) Network() string { return "tcp" }
func (a staticAddr) String() string  { return a.s }

type stubConn struct {
	net.Conn
	remote net.Addr
}

func (s stubConn) RemoteAddr() net.Addr { return s.remote }

func TestClient_ConnectedIPParsesRemoteAddr(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want string
	}{
		{"hostport ipv4", "127.0.0.1:50301", "127.0.0.1"},
		{"hostport ipv6 bracketed", "[::1]:50301", "::1"},
		{"url with ipv4", "rel://127.0.0.1:50301", "127.0.0.1"},
		{"url with ipv6", "rels://[2001:db8::1]:443", "2001:db8::1"},
		{"fqdn url returns empty", "rel://relay.example.com:50301", ""},
		{"fqdn hostport returns empty", "relay.example.com:50301", ""},
		{"plain ipv4 no port", "10.0.0.1", "10.0.0.1"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{relayConn: stubConn{remote: staticAddr{s: tt.s}}}
			got := c.ConnectedIP()
			var gotStr string
			if got.IsValid() {
				gotStr = got.String()
			}
			if gotStr != tt.want {
				t.Errorf("ConnectedIP(%q) = %q, want %q", tt.s, gotStr, tt.want)
			}
		})
	}
}

// freeAddr returns a 127.0.0.1 address with an OS-assigned port. The
// listener is closed before returning, so the port is briefly free for
// the caller to bind. Avoids hardcoded ports that can collide.
func freeAddr(t *testing.T) (string, int) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("get free port: %s", err)
	}
	addr := l.Addr().(*net.TCPAddr)
	_ = l.Close()
	return addr.String(), addr.Port
}
