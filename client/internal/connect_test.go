package internal

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/management/server/account"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
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

// TestLoginOrReRegister checks when a denied login is retried through Register, against a mock management client.
func TestLoginOrReRegister(t *testing.T) {
	denied := gstatus.Error(codes.PermissionDenied, "peer is not registered")
	unavailable := gstatus.Error(codes.Unavailable, "management unreachable")
	registered := &proto.LoginResponse{NetbirdConfig: &proto.NetbirdConfig{}}
	loggedIn := &proto.LoginResponse{PeerConfig: &proto.PeerConfig{}}

	tests := []struct {
		name         string
		setupKey     string
		reRegister   string
		loginResp    *proto.LoginResponse
		loginErr     error
		registerErr  error
		wantResp     *proto.LoginResponse
		wantCode     codes.Code
		wantRegister bool
	}{
		{
			name:      "login succeeds",
			setupKey:  "secret-key",
			loginResp: loggedIn,
			wantResp:  loggedIn,
			wantCode:  codes.OK,
		},
		{
			name:         "login denied, setup key set, register succeeds",
			setupKey:     "secret-key",
			reRegister:   "true",
			loginErr:     denied,
			wantResp:     registered,
			wantCode:     codes.OK,
			wantRegister: true,
		},
		{
			name:         "login denied, setup key set, register fails",
			setupKey:     "secret-key",
			reRegister:   "true",
			loginErr:     denied,
			registerErr:  gstatus.Error(codes.PermissionDenied, "peer login has expired"),
			wantCode:     codes.PermissionDenied,
			wantRegister: true,
		},
		{
			name:       "login denied, no setup key",
			reRegister: "true",
			loginErr:   denied,
			wantCode:   codes.PermissionDenied,
		},
		{
			name:     "login denied, setup key set, not opted in",
			setupKey: "secret-key",
			loginErr: denied,
			wantCode: codes.PermissionDenied,
		},
		{
			name:       "login denied, setup key set, unparsable opt-in",
			setupKey:   "secret-key",
			reRegister: "maybe",
			loginErr:   denied,
			wantCode:   codes.PermissionDenied,
		},
		{
			name:       "login unavailable, setup key set",
			setupKey:   "secret-key",
			reRegister: "true",
			loginErr:   unavailable,
			wantCode:   codes.Unavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(envSetupKey, tt.setupKey)
			t.Setenv(envReRegister, tt.reRegister)

			var registerCalled bool
			client := &mgm.MockClient{
				LoginFunc: func(*system.Info, []byte, domain.List) (*proto.LoginResponse, error) {
					return tt.loginResp, tt.loginErr
				},
				RegisterFunc: func(string, string, *system.Info, []byte, domain.List) (*proto.LoginResponse, error) {
					registerCalled = true
					if tt.registerErr != nil {
						return nil, tt.registerErr
					}
					return registered, nil
				},
			}

			resp, err := loginOrReRegister(context.Background(), client, []byte("ssh-stub"), &profilemanager.Config{})

			if registerCalled != tt.wantRegister {
				t.Errorf("Register called = %v, want %v", registerCalled, tt.wantRegister)
			}
			if resp != tt.wantResp {
				t.Errorf("response = %v, want %v", resp, tt.wantResp)
			}
			if got := gstatus.Code(err); got != tt.wantCode {
				t.Errorf("error code = %v, want %v (err: %v)", got, tt.wantCode, err)
			}
			if tt.loginErr != nil && err != nil && err != tt.loginErr {
				t.Errorf("error = %v, want the original login error %v", err, tt.loginErr)
			}
		})
	}
}

// TestReRegisterWithEnvSetupKey checks how the retry reads NB_SETUP_KEY and reports a failed Register.
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

// TestLoginOrReRegisterAgainstManagement runs the recovery path against a real
// management server: the peer is deleted on the server, as ephemeral cleanup or
// an admin would do, and the next login has to enroll it again.
func TestLoginOrReRegisterAgainstManagement(t *testing.T) {
	const (
		accountID = "bf1c8084-ba50-4ce7-9439-34653001fc3b"
		adminID   = "edafee4e-63fb-11ec-90d6-0242ac120003"
		setupKey  = "A2C8E62B-38F5-4553-B31E-DD66C696CEBB"
	)

	tests := []struct {
		name       string
		envKey     string
		reRegister string
		wantCode   codes.Code
	}{
		{name: "setup key set, peer enrolled again", envKey: setupKey, reRegister: "true", wantCode: codes.OK},
		{name: "setup key set, not opted in, login stays denied", envKey: setupKey, wantCode: codes.PermissionDenied},
		{name: "no setup key, login stays denied", reRegister: "true", wantCode: codes.PermissionDenied},
		{name: "unknown setup key, login stays denied", envKey: "00000000-0000-0000-0000-000000000000", reRegister: "true", wantCode: codes.PermissionDenied},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			_, addr, accountManager, err := startManagementServer(t, t.TempDir(), "../testdata/store.sql")
			require.NoError(t, err)

			key, err := wgtypes.GeneratePrivateKey()
			require.NoError(t, err)
			client, err := mgm.NewClient(ctx, addr, key, false)
			require.NoError(t, err)
			t.Cleanup(func() { _ = client.Close() })

			config := &profilemanager.Config{}
			_, err = client.Register(setupKey, "", buildLoginSysInfo(ctx, config), nil, nil)
			require.NoError(t, err)

			peer := peerByKey(t, accountManager, accountID, adminID, key.PublicKey().String())
			require.NotNil(t, peer, "peer was not registered")
			require.NoError(t, accountManager.DeletePeer(ctx, accountID, peer.ID, adminID))

			t.Setenv(envSetupKey, tt.envKey)
			t.Setenv(envReRegister, tt.reRegister)
			resp, err := loginOrReRegister(ctx, client, nil, config)

			require.Equal(t, tt.wantCode, gstatus.Code(err), "error: %v", err)
			if tt.wantCode != codes.OK {
				require.Nil(t, resp)
				return
			}
			require.NotNil(t, resp.GetPeerConfig())
			require.NotNil(t, peerByKey(t, accountManager, accountID, adminID, key.PublicKey().String()), "peer was not enrolled again")
		})
	}
}

// peerByKey returns the account's peer with the given WireGuard public key, or nil.
func peerByKey(t *testing.T, am account.Manager, accountID, userID, key string) *nbpeer.Peer {
	t.Helper()

	peers, err := am.GetPeers(context.Background(), accountID, userID, "", "", "")
	require.NoError(t, err)
	for _, p := range peers {
		if p.Key == key {
			return p
		}
	}
	return nil
}
