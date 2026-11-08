package ws

import (
	"net/url"
	"testing"

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
