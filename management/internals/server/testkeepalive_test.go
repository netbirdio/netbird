package server

import (
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c" //nolint:staticcheck
)

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestParseTestKeepalive(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want testKeepalive
	}{
		{name: "unset", env: nil, want: testKeepalive{}},
		{name: "grpc set", env: map[string]string{envGRPCServerKASec: "25"}, want: testKeepalive{grpcTime: 25 * time.Second}},
		{name: "grpc zero ignored", env: map[string]string{envGRPCServerKASec: "0"}, want: testKeepalive{}},
		{name: "grpc negative ignored", env: map[string]string{envGRPCServerKASec: "-5"}, want: testKeepalive{}},
		{name: "grpc garbage ignored", env: map[string]string{envGRPCServerKASec: "abc"}, want: testKeepalive{}},
		{name: "tcp off", env: map[string]string{envServerTCPKASec: "-1"}, want: testKeepalive{tcpSet: true, tcp: -1}},
		{name: "tcp set", env: map[string]string{envServerTCPKASec: "120"}, want: testKeepalive{tcpSet: true, tcp: 120 * time.Second}},
		{name: "tcp zero ignored", env: map[string]string{envServerTCPKASec: "0"}, want: testKeepalive{}},
		{name: "tcp -2 ignored", env: map[string]string{envServerTCPKASec: "-2"}, want: testKeepalive{}},
		{name: "tcp garbage ignored", env: map[string]string{envServerTCPKASec: "1m"}, want: testKeepalive{}},
		{
			name: "both",
			env:  map[string]string{envGRPCServerKASec: "30", envServerTCPKASec: "-1"},
			want: testKeepalive{grpcTime: 30 * time.Second, tcpSet: true, tcp: -1},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseTestKeepalive(envMap(tt.env))
			assert.Equal(t, tt.want, got, "parsed config")
		})
	}
}

func TestTestKeepaliveServerParams(t *testing.T) {
	assert.Equal(t, kasp, testKeepalive{}.serverParams(), "unset env must keep stock params")

	got := testKeepalive{grpcTime: 25 * time.Second}.serverParams()
	want := kasp
	want.Time = 25 * time.Second
	assert.Equal(t, want, got, "only Time changes")
}

func TestTestKeepaliveH2CServer(t *testing.T) {
	assert.Equal(t, &http2.Server{}, testKeepalive{}.h2cServer(), "unset env must keep stock h2c server")

	got := testKeepalive{grpcTime: 7 * time.Second}.h2cServer()
	assert.Equal(t, 7*time.Second, got.ReadIdleTimeout, "ping after idle")
	assert.Equal(t, kasp.Timeout, got.PingTimeout, "ping timeout matches gRPC timeout")
}

// The shared port serves gRPC through net/http's HTTP/2 server, so the server
// keepalive there is an HTTP/2 PING sent after a read-idle period. Connect a
// raw HTTP/2 client, stay silent and expect a PING from the server.
func TestTestKeepaliveH2CServerSendsPing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	ka := testKeepalive{grpcTime: time.Second}
	srv := &http.Server{Handler: h2c.NewHandler(http.NotFoundHandler(), ka.h2cServer())}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	_, err = conn.Write([]byte(http2.ClientPreface))
	require.NoError(t, err)
	fr := http2.NewFramer(conn, conn)
	require.NoError(t, fr.WriteSettings())

	start := time.Now()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	for {
		f, err := fr.ReadFrame()
		require.NoError(t, err, "server must send a PING before the deadline")
		if sf, ok := f.(*http2.SettingsFrame); ok && !sf.IsAck() {
			require.NoError(t, fr.WriteSettingsAck())
			continue
		}
		if pf, ok := f.(*http2.PingFrame); ok && !pf.IsAck() {
			elapsed := time.Since(start)
			assert.GreaterOrEqual(t, elapsed, 900*time.Millisecond, "PING must wait for the idle period")
			return
		}
	}
}
