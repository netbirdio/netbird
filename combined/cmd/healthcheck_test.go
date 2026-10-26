package cmd

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/relay/healthcheck"
	"github.com/netbirdio/netbird/relay/protocol"
	relayServer "github.com/netbirdio/netbird/relay/server"
	"github.com/netbirdio/netbird/relay/server/listener/ws"
	"github.com/netbirdio/netbird/shared/relay"
	"github.com/netbirdio/netbird/shared/relay/auth"
)

// The relay runs here the way the combined server runs it: Listen is never
// called and the WebSocket endpoint is served from the management port.
func TestHealthcheckReportsMultiplexedRelay(t *testing.T) {
	mgmtListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	relaySrv, err := relayServer.NewServer(relayServer.Config{
		ExposedAddress: "rel://" + mgmtListener.Addr().String(),
		AuthValidator:  auth.NewTimedHMACValidator([]byte("secret")),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = relaySrv.Shutdown(context.Background()) })
	require.Empty(t, relaySrv.ListenerProtocols())

	mux := http.NewServeMux()
	mux.HandleFunc(relay.WebSocketURLPath, func(w http.ResponseWriter, r *http.Request) {
		handleRelayWebSocket(w, r, relaySrv.RelayAccept(), nil)
	})
	mgmt := &http.Server{Handler: mux, ReadHeaderTimeout: time.Second}
	go func() { _ = mgmt.Serve(mgmtListener) }()
	t.Cleanup(func() { _ = mgmt.Shutdown(context.Background()) })

	servers := &serverInstances{relaySrv: relaySrv}
	cfg := &CombinedConfig{Server: ServerConfig{HealthcheckAddress: freeAddress(t)}}
	require.NoError(t, servers.createHealthcheckServer(cfg))
	go func() { _ = servers.healthcheck.ListenAndServe() }()
	t.Cleanup(func() { _ = servers.healthcheck.Shutdown(context.Background()) })

	resp := getHealth(t, "http://"+cfg.Server.HealthcheckAddress+"/health")
	defer resp.Body.Close()
	var status healthcheck.HealthStatus
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&status))
	require.Equal(t, http.StatusOK, resp.StatusCode, status)
	require.Equal(t, []protocol.Protocol{ws.Proto}, status.Listeners)
}

func freeAddress(t *testing.T) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	require.NoError(t, lis.Close())
	return lis.Addr().String()
}

// getHealth retries until the health check server is listening.
func getHealth(t *testing.T, url string) *http.Response {
	t.Helper()
	client := &http.Client{Timeout: time.Second}
	var resp *http.Response
	require.Eventually(t, func() bool {
		var err error
		resp, err = client.Get(url)
		return err == nil
	}, 5*time.Second, 50*time.Millisecond)
	return resp
}
