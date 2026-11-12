package ws

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	nbnet "github.com/netbirdio/netbird/client/net"
	"github.com/netbirdio/netbird/shared/relay"
	"github.com/netbirdio/netbird/shared/testhb"
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

func TestWithTestHB(t *testing.T) {
	const value = "p=17342;period=30;t=1762600000123"
	for _, in := range []string{"wss://relay.example.com/relay", "ws://relay.example.com:8080/relay", "wss://relay.example.com/relay?x=1"} {
		got := withTestHB(in, value)
		u, err := url.Parse(got)
		if err != nil {
			t.Fatalf("withTestHB(%q) = %q: %v", in, got, err)
		}
		orig, _ := url.Parse(in)
		if u.Scheme != orig.Scheme || u.Host != orig.Host || u.Path != relay.WebSocketURLPath {
			t.Errorf("withTestHB(%q) = %q: scheme, host or path changed", in, got)
		}
		if v := u.Query().Get(testhb.RelayQueryParam); v != value {
			t.Errorf("withTestHB(%q) nbhb = %q, want %q", in, v, value)
		}
		for k, vs := range orig.Query() {
			if u.Query().Get(k) != vs[0] {
				t.Errorf("withTestHB(%q) lost query %s", in, k)
			}
		}
	}

	// The full path from a relay address keeps the /relay path.
	wsURL, err := prepareURL("rels://relay.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := withTestHB(wsURL, value), "wss://relay.example.com:443/relay?nbhb=p%3D17342%3Bperiod%3D30%3Bt%3D1762600000123"; got != want {
		t.Errorf("withTestHB = %q, want %q", got, want)
	}
}

func TestRelayTCPDialerKeepAliveOffWithTestHB(t *testing.T) {
	t.Setenv("NB_TEST_TCP_KEEPALIVE_SEC", "")
	t.Setenv(testhb.EnvDynamic, "1")
	t.Setenv(testhb.EnvPeriod, "60")

	// With the test heartbeat on, the shared base dialer enables keepalive.
	// That config wins over a negative KeepAlive, so it has to be cleared.
	if !nbnet.NewDialer().KeepAliveConfig.Enable {
		t.Fatal("precondition: base dialer should enable KeepAliveConfig with the test heartbeat on")
	}

	d := relayTCPDialer()
	if d.KeepAlive >= 0 {
		t.Errorf("KeepAlive = %v, want negative (off)", d.KeepAlive)
	}
	if d.KeepAliveConfig.Enable {
		t.Errorf("KeepAliveConfig.Enable = true, want false so the negative KeepAlive applies")
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
