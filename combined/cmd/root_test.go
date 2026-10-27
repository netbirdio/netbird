package cmd

import (
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/metric/noop"

	sharedMetrics "github.com/netbirdio/netbird/shared/metrics"
)

func freeUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	port := conn.LocalAddr().(*net.UDPAddr).Port
	require.NoError(t, conn.Close())
	return port
}

// createNetworkServices builds the local relay and STUN servers the way
// createAllServers does, so the tests do not depend on how that is split.
func createNetworkServices(t *testing.T, cfg *CombinedConfig) *serverInstances {
	t.Helper()
	s := &serverInstances{
		metricsServer: &sharedMetrics.Metrics{Meter: noop.NewMeterProvider().Meter("test")},
	}
	t.Cleanup(func() { cleanupSTUNListeners(s.stunListeners) })
	require.NoError(t, s.createSTUNServer(cfg))
	require.NoError(t, s.createRelayServer(cfg, false))
	return s
}

func stunListenerPorts(s *serverInstances) []int {
	var ports []int
	for _, l := range s.stunListeners {
		ports = append(ports, l.LocalAddr().(*net.UDPAddr).Port)
	}
	return ports
}

func TestCreateNetworkServices(t *testing.T) {
	t.Run("embedded relay and STUN", func(t *testing.T) {
		port := freeUDPPort(t)
		cfg := loadTestConfig(t, baseServerYAML+fmt.Sprintf("  stunPorts: [%d]\n", port))

		s := createNetworkServices(t, cfg)

		assert.NotNil(t, s.relaySrv, "local relay server")
		assert.NotNil(t, s.stunServer, "local STUN server")
		assert.Equal(t, []int{port}, stunListenerPorts(s), "STUN listens on the configured port")
	})

	t.Run("external STUN keeps the local relay only", func(t *testing.T) {
		cfg := loadTestConfig(t, baseServerYAML+`
  stuns:
    - uri: "stun:stun.example.com:3478"
`)

		s := createNetworkServices(t, cfg)

		assert.NotNil(t, s.relaySrv, "local relay server")
		assert.Nil(t, s.stunServer, "no local STUN server")
		assert.Empty(t, s.stunListeners, "no STUN listeners")
	})

	t.Run("external relay turns off the local relay and STUN", func(t *testing.T) {
		cfg := loadTestConfig(t, baseServerYAML+`
  relays:
    addresses: ["rels://relay.example.com:443"]
`)

		s := createNetworkServices(t, cfg)

		assert.Nil(t, s.relaySrv, "no local relay server")
		assert.Nil(t, s.stunServer, "no local STUN server")
		assert.Empty(t, s.stunListeners, "no STUN listeners")
	})

	t.Run("disableRelay keeps local STUN running", func(t *testing.T) {
		port := freeUDPPort(t)
		cfg := loadTestConfig(t, baseServerYAML+fmt.Sprintf("  disableRelay: true\n  stunPorts: [%d]\n", port))

		s := createNetworkServices(t, cfg)

		assert.Nil(t, s.relaySrv, "no local relay server")
		assert.NotNil(t, s.stunServer, "local STUN server")
		assert.Equal(t, []int{port}, stunListenerPorts(s), "STUN listens on the configured port")
	})

	t.Run("disableStun keeps the local relay only", func(t *testing.T) {
		cfg := loadTestConfig(t, baseServerYAML+"  disableStun: true\n")

		s := createNetworkServices(t, cfg)

		assert.NotNil(t, s.relaySrv, "local relay server")
		assert.Nil(t, s.stunServer, "no local STUN server")
		assert.Empty(t, s.stunListeners, "no STUN listeners")
	})

	t.Run("keepEmbeddedStun runs local STUN next to external STUN", func(t *testing.T) {
		port := freeUDPPort(t)
		cfg := loadTestConfig(t, baseServerYAML+fmt.Sprintf(`
  keepEmbeddedStun: true
  stunPorts: [%d]
  stuns:
    - uri: "stun:stun.example.com:3478"
`, port))

		s := createNetworkServices(t, cfg)

		assert.NotNil(t, s.relaySrv, "local relay server")
		assert.NotNil(t, s.stunServer, "local STUN server")
		assert.Equal(t, []int{port}, stunListenerPorts(s), "STUN listens on the configured port")
	})

	t.Run("keepEmbeddedRelay runs the local relay next to external relays", func(t *testing.T) {
		cfg := loadTestConfig(t, baseServerYAML+`
  keepEmbeddedRelay: true
  relays:
    addresses: ["rels://relay.example.com:443"]
  stuns:
    - uri: "stun:relay.example.com:3478"
`)

		s := createNetworkServices(t, cfg)

		assert.NotNil(t, s.relaySrv, "local relay server")
		assert.Nil(t, s.stunServer, "no local STUN server")
	})
}

func TestCreateHealthcheckServer(t *testing.T) {
	t.Run("runs with the local relay", func(t *testing.T) {
		cfg := loadTestConfig(t, baseServerYAML+"  disableStun: true\n")
		s := createNetworkServices(t, cfg)

		require.NoError(t, s.createHealthcheckServer(cfg))
		assert.NotNil(t, s.healthcheck, "healthcheck server checks the local relay")
	})

	// Without a local relay the healthcheck has nothing to probe. Wiring the nil
	// relay into it used to panic on the first /health request.
	cases := map[string]string{
		"disableRelay": "  disableRelay: true\n  disableStun: true\n",
		"external relay": `
  relays:
    addresses: ["rels://relay.example.com:443"]
  stuns:
    - uri: "stun:relay.example.com:3478"
`,
	}
	for name, extra := range cases {
		t.Run(name+" skips the healthcheck", func(t *testing.T) {
			cfg := loadTestConfig(t, baseServerYAML+extra)
			s := createNetworkServices(t, cfg)

			require.NoError(t, s.createHealthcheckServer(cfg))
			assert.Nil(t, s.healthcheck, "no healthcheck server without a local relay")
		})
	}
}
