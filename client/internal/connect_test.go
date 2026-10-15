package internal

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/system"
	mgm "github.com/netbirdio/netbird/shared/management/client"
	"github.com/netbirdio/netbird/shared/management/domain"
	"github.com/netbirdio/netbird/shared/management/proto"
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

func TestReRegisterWithEnvSetupKey(t *testing.T) {
	pubSSHKey := []byte("ssh-stub")
	config := &profilemanager.Config{}

	t.Run("no env var, returns nil", func(t *testing.T) {
		t.Setenv(envSetupKey, "")
		if err := os.Unsetenv(envSetupKey); err != nil {
			t.Fatalf("unset %s: %v", envSetupKey, err)
		}

		var registerCalled bool
		client := &mgm.MockClient{
			RegisterFunc: func(string, string, *system.Info, []byte, domain.List) (*proto.LoginResponse, error) {
				registerCalled = true
				return &proto.LoginResponse{}, nil
			},
		}

		if got := reRegisterWithEnvSetupKey(context.Background(), client, pubSSHKey, config); got != nil {
			t.Fatalf("expected nil without env var, got %v", got)
		}
		if registerCalled {
			t.Fatal("Register must not be called when the env var is unset")
		}
	})

	t.Run("env var set, Register succeeds, response is returned", func(t *testing.T) {
		t.Setenv(envSetupKey, "  secret-key  ") // whitespace must be trimmed

		var gotKey string
		want := &proto.LoginResponse{NetbirdConfig: &proto.NetbirdConfig{}}
		client := &mgm.MockClient{
			RegisterFunc: func(setupKey, _ string, _ *system.Info, _ []byte, _ domain.List) (*proto.LoginResponse, error) {
				gotKey = setupKey
				return want, nil
			},
		}

		got := reRegisterWithEnvSetupKey(context.Background(), client, pubSSHKey, config)
		if got != want {
			t.Fatalf("expected the Register response to be returned verbatim, got %v", got)
		}
		if gotKey != "secret-key" {
			t.Fatalf("expected setup key to be trimmed to %q, got %q", "secret-key", gotKey)
		}
	})

	t.Run("env var set, Register fails, returns nil so caller falls through", func(t *testing.T) {
		t.Setenv(envSetupKey, "secret-key")

		client := &mgm.MockClient{
			RegisterFunc: func(string, string, *system.Info, []byte, domain.List) (*proto.LoginResponse, error) {
				return nil, errors.New("key revoked")
			},
		}

		if got := reRegisterWithEnvSetupKey(context.Background(), client, pubSSHKey, config); got != nil {
			t.Fatalf("expected nil on Register failure, got %v", got)
		}
	})
}
