package internal

import (
	"net"
	"testing"
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
