package internal

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	cProto "github.com/netbirdio/netbird/client/proto"
)

// probeFreePort asks the OS for a free UDP port and immediately releases it.
// The returned number is only a hint: nothing stops another process from
// grabbing the same port before the caller gets a chance to bind it.
//
// A hardcoded port number is not an option here: any fixed number can fall
// inside the ephemeral range and be held by an unrelated process on the test
// runner.
func probeFreePort(t *testing.T) int {
	t.Helper()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		t.Fatalf("failed to bind probe port: %v", err)
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	if err := conn.Close(); err != nil {
		t.Fatalf("failed to close probe port: %v", err)
	}
	return port
}

func Test_freePort(t *testing.T) {
	t.Run("when port is 0 use random port", func(t *testing.T) {
		got, err := freePort(0)
		if err != nil {
			t.Fatalf("got an error while getting free port: %v", err)
		}
		if got == 0 {
			t.Errorf("got port 0, want a non-zero random port")
		}
	})

	t.Run("provided and available", func(t *testing.T) {
		const maxAttempts = 5

		// The probed port is released before freePort binds it, so an
		// unrelated process on the test runner can grab it in between,
		// making freePort fall back to a different port. Retry with a
		// freshly probed port instead of failing on a lost race.
		for attempt := 1; attempt <= maxAttempts; attempt++ {
			candidate := probeFreePort(t)

			got, err := freePort(candidate)
			if err != nil {
				t.Fatalf("got an error while getting free port: %v", err)
			}

			if got == candidate {
				return
			}
			t.Logf("attempt %d: freePort returned %d instead of the requested %d, retrying", attempt, got, candidate)
		}

		t.Fatalf("freePort did not return the requested free port after %d attempts", maxAttempts)
	})

	t.Run("provided and not available", func(t *testing.T) {
		busy, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
		if err != nil {
			t.Fatalf("failed to bind busy port: %v", err)
		}
		t.Cleanup(func() {
			_ = busy.Close()
		})
		busyPort := busy.LocalAddr().(*net.UDPAddr).Port

		got, err := freePort(busyPort)
		if err != nil {
			t.Fatalf("got an error while getting free port: %v", err)
		}
		if got == busyPort {
			t.Errorf("got the same port %v, want a different port", busyPort)
		}
	})
}

// A holder on any one socket kind must make the port unusable. wireguard-go
// binds udp4 and udp6, and some platforms only report a conflict between
// sockets of the same kind, so a dual-stack holder is checked as well.
func Test_freePort_singleFamilyHolder(t *testing.T) {
	for _, network := range []string{"udp", "udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			busy, err := net.ListenUDP(network, &net.UDPAddr{Port: 0})
			if err != nil {
				t.Skipf("%s not available: %v", network, err)
			}
			t.Cleanup(func() {
				_ = busy.Close()
			})
			busyPort := busy.LocalAddr().(*net.UDPAddr).Port

			got, err := freePort(busyPort)
			require.NoError(t, err)
			assert.NotEqual(t, busyPort, got, "port held on %s must not be returned", network)
		})
	}
}

func TestNotifyWgPortFallback(t *testing.T) {
	newClient := func(configured int) *ConnectClient {
		return &ConnectClient{
			config:         &profilemanager.Config{WgPort: configured},
			statusRecorder: peer.NewRecorder(""),
		}
	}

	t.Run("publishes a warning when the port changed", func(t *testing.T) {
		c := newClient(51820)
		c.notifyWgPortFallback(40000)

		events := c.statusRecorder.GetEventHistory()
		require.Len(t, events, 1)
		assert.Equal(t, cProto.SystemEvent_WARNING, events[0].Severity)
		assert.Equal(t, "40000", events[0].Metadata["port"])
		assert.Equal(t, "51820", events[0].Metadata["configured_port"])
	})

	t.Run("publishes once across reconnect cycles", func(t *testing.T) {
		c := newClient(51820)
		// every cycle draws a different random fallback port
		c.notifyWgPortFallback(40000)
		c.notifyWgPortFallback(40001)
		c.notifyWgPortFallback(40002)
		assert.Len(t, c.statusRecorder.GetEventHistory(), 1)
	})

	t.Run("publishes again after the configured port recovered", func(t *testing.T) {
		c := newClient(51820)
		c.notifyWgPortFallback(40000)
		c.notifyWgPortFallback(51820)
		c.notifyWgPortFallback(40001)
		assert.Len(t, c.statusRecorder.GetEventHistory(), 2)
	})

	t.Run("silent when the configured port is used", func(t *testing.T) {
		c := newClient(51820)
		c.notifyWgPortFallback(51820)
		assert.Empty(t, c.statusRecorder.GetEventHistory())
	})

	t.Run("silent when a random port was requested", func(t *testing.T) {
		c := newClient(0)
		c.notifyWgPortFallback(40000)
		assert.Empty(t, c.statusRecorder.GetEventHistory())
	})
}
