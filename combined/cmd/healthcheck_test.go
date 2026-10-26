package cmd

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/relay/healthcheck"
	"github.com/netbirdio/netbird/relay/protocol"
	relayServer "github.com/netbirdio/netbird/relay/server"
	"github.com/netbirdio/netbird/relay/server/listener/ws"
	"github.com/netbirdio/netbird/shared/relay/auth"
)

func TestHealthcheckSeesMultiplexedRelayListener(t *testing.T) {
	srv, err := relayServer.NewServer(relayServer.Config{
		ExposedAddress: "rels://relay.example.com:443",
		TLSSupport:     true,
		AuthValidator:  auth.NewTimedHMACValidator([]byte("secret")),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	// Listen is never called in the combined server, so the relay itself has
	// nothing to report and the health check would stay unhealthy.
	require.Empty(t, srv.ListenerProtocols())

	var checker healthcheck.ServiceChecker = multiplexedRelay{srv}
	require.Equal(t, []protocol.Protocol{ws.Proto}, checker.ListenerProtocols())
	require.Equal(t, "rels", checker.InstanceURL().Scheme)
}
