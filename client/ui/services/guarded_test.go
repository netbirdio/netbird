//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/elevate"
	"github.com/netbirdio/netbird/client/internal/ipcauth"
	"github.com/netbirdio/netbird/client/proto"
)

// A Unix socket, so the daemon address is one that carries a caller's identity and
// elevation is worth offering at all: see Settings.canElevate.
const testDaemonAddr = "unix:///var/run/netbird.sock"

// stubElevator stands in for the platform's prompt: it records what would have run
// and answers with a fixed outcome.
type stubElevator struct {
	outcome   error
	available bool
	calls     [][]string
}

func (e *stubElevator) Run(_ context.Context, args ...string) error {
	e.calls = append(e.calls, args)
	return e.outcome
}

func (e *stubElevator) Available() bool { return e.available }

// stubDaemon implements only the RPC under test. The embedded interface is nil, so
// any other call panics rather than passing quietly.
type stubDaemon struct {
	proto.DaemonServiceClient
	setConfig func(*proto.SetConfigRequest) error
	requests  []*proto.SetConfigRequest
}

func (d *stubDaemon) SetConfig(_ context.Context, in *proto.SetConfigRequest, _ ...grpc.CallOption) (*proto.SetConfigResponse, error) {
	d.requests = append(d.requests, in)
	if err := d.setConfig(in); err != nil {
		return nil, err
	}
	return &proto.SetConfigResponse{}, nil
}

type stubConn struct{ client proto.DaemonServiceClient }

func (c stubConn) Client() (proto.DaemonServiceClient, error) { return c.client, nil }

// privilegeRefusal is the error the daemon raises for a change it restricts to
// root, detail and all: see server.privilegeError.
func privilegeRefusal(t *testing.T) error {
	t.Helper()

	st, err := gstatus.New(codes.PermissionDenied, "Changing the management URL requires root.").
		WithDetails(&errdetails.ErrorInfo{
			Reason: ipcauth.ErrorReasonPrivilegeRequired,
			Domain: ipcauth.ErrorDomain,
			Metadata: map[string]string{
				ipcauth.ErrorMetaSummary: "Changing the management URL requires root.",
				ipcauth.ErrorMetaCommand: "sudo netbird down; sudo netbird up -m https://mgmt.example.com",
			},
		})
	require.NoError(t, err, "build the refusal detail")
	return st.Err()
}

func settingsWithElevation(t *testing.T, outcome error) (*Settings, *stubElevator) {
	t.Helper()

	elev := &stubElevator{outcome: outcome, available: true}
	return &Settings{daemonAddr: testDaemonAddr, elevator: elev}, elev
}

// settingsRefusingOnce returns a Settings whose daemon refuses the first SetConfig
// for want of privileges and accepts anything after it.
func settingsRefusingOnce(t *testing.T, elev *stubElevator) (*Settings, *stubDaemon) {
	t.Helper()

	refusal := privilegeRefusal(t)
	daemon := &stubDaemon{}
	daemon.setConfig = func(*proto.SetConfigRequest) error {
		if len(daemon.requests) == 1 {
			return refusal
		}
		return nil
	}
	return &Settings{conn: stubConn{client: daemon}, daemonAddr: testDaemonAddr, elevator: elev}, daemon
}

func TestSetGuardedSettingsPassesOnlyTheChangedSettings(t *testing.T) {
	s, elev := settingsWithElevation(t, nil)

	root := true
	outcome, err := s.SetGuardedSettings(context.Background(), GuardedSettings{
		ProfileName:   "work",
		Username:      "vma",
		EnableSSHRoot: &root,
	})
	require.NoError(t, err)
	assert.False(t, outcome.Declined, "the prompt was answered")

	want := []string{
		"--" + FlagApplyPrivilegedSettings,
		"--" + FlagDaemonAddr, testDaemonAddr,
		"--" + FlagProfile, "work",
		"--" + FlagUser, "vma",
		"--" + FlagEnableSSHRoot + "=true",
	}
	require.Len(t, elev.calls, 1, "one prompt for one change")
	assert.Equal(t, want, elev.calls[0], "elevated arguments")
}

// Turning a setting off has to be as explicit as turning it on: a bare flag would
// read as "on" to the one-shot's parser.
func TestSetGuardedSettingsSpellsOutFalse(t *testing.T) {
	s, elev := settingsWithElevation(t, nil)

	off := false
	_, err := s.SetGuardedSettings(context.Background(), GuardedSettings{
		ProfileName:      "default",
		ServerSSHAllowed: &off,
		DisableSSHAuth:   &off,
	})
	require.NoError(t, err)

	args := elev.calls[0]
	assert.Contains(t, args, "--"+FlagAllowServerSSH+"=false", "the setting being switched off")
	assert.Contains(t, args, "--"+FlagDisableSSHAuth+"=false", "the setting being switched off")
	assert.NotContains(t, args, "--"+FlagEnableSSHRoot+"=false", "no flag for a setting nobody touched")
}

func TestSetGuardedSettingsPassesTheManagementURL(t *testing.T) {
	s, elev := settingsWithElevation(t, nil)

	_, err := s.SetGuardedSettings(context.Background(), GuardedSettings{
		ProfileName:   "default",
		ManagementURL: "https://mgmt.example.com:33073",
	})
	require.NoError(t, err)

	assert.Contains(t, elev.calls[0], "--"+FlagManagementURL+"=https://mgmt.example.com:33073",
		"the management URL to point the profile at")
}

func TestSetGuardedSettingsWithoutASettingDoesNotElevate(t *testing.T) {
	s, elev := settingsWithElevation(t, nil)

	_, err := s.SetGuardedSettings(context.Background(), GuardedSettings{ProfileName: "default"})

	require.Error(t, err, "nothing to apply is not something to prompt for")
	assert.Empty(t, elev.calls, "no prompt at all")
}

// A declined prompt is the one ending that is not an error: reporting it as one
// would have every cancelled prompt logged as a failure.
func TestSetGuardedSettingsReportsADeclinedPromptAsAnOutcome(t *testing.T) {
	s, _ := settingsWithElevation(t, elevate.ErrDeclined)

	root := true
	outcome, err := s.SetGuardedSettings(context.Background(), GuardedSettings{
		ProfileName:   "default",
		EnableSSHRoot: &root,
	})

	require.NoError(t, err, "the user was asked and answered; nothing went wrong")
	assert.True(t, outcome.Declined, "nothing was applied")
}

func TestSetGuardedSettingsMapsFailures(t *testing.T) {
	tests := []struct {
		name     string
		outcome  error
		wantCode string
	}{
		{
			// Nothing to raise a prompt with: the user needs the command.
			name:     "no mechanism falls back to the command",
			outcome:  elevate.ErrUnavailable,
			wantCode: CodeElevationUnavailable,
		},
		{
			name:     "a failed run falls back to the command",
			outcome:  errors.New("elevated netbird exited with 1"),
			wantCode: CodeElevationFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, _ := settingsWithElevation(t, tt.outcome)

			root := true
			_, err := s.SetGuardedSettings(context.Background(), GuardedSettings{
				ProfileName:   "default",
				EnableSSHRoot: &root,
			})

			var clientErr *ClientError
			require.ErrorAs(t, err, &clientErr, "the frontend needs a code to act on")
			assert.Equal(t, tt.wantCode, clientErr.Code, "error code")
			assert.Contains(t, clientErr.Command, "--"+FlagEnableSSHRoot+"=true",
				"the setting in the fallback command")
			assert.Contains(t, clientErr.Command, "netbird up", "the fallback command")
		})
	}
}

// Changing the management URL is only privileged while the host runs the SSH
// server, which no control can know up front, so the refusal is what triggers the
// prompt. The original request goes again afterwards, so the fields the one-shot
// does not understand are applied too.
func TestSetConfigElevatesAfterARefusalAndRetries(t *testing.T) {
	elev := &stubElevator{available: true}
	s, daemon := settingsRefusingOnce(t, elev)

	mtu := int64(1280)
	outcome, err := s.SetConfig(context.Background(), SetConfigParams{
		ProfileName:   "default",
		ManagementURL: "https://mgmt.example.com",
		MTU:           &mtu,
	})
	require.NoError(t, err)
	assert.False(t, outcome.Declined, "the prompt was answered")

	require.Len(t, elev.calls, 1, "one prompt")
	assert.Contains(t, elev.calls[0], "--"+FlagManagementURL+"=https://mgmt.example.com",
		"the guarded part of the request")
	require.Len(t, daemon.requests, 2, "the refused request and the retry")
	assert.Equal(t, mtu, daemon.requests[1].GetMtu(),
		"the retry carries the rest of the request, which the one-shot does not understand")
}

func TestSetConfigDoesNotRetryWhenTheUserDeclines(t *testing.T) {
	elev := &stubElevator{outcome: elevate.ErrDeclined, available: true}
	s, daemon := settingsRefusingOnce(t, elev)

	outcome, err := s.SetConfig(context.Background(), SetConfigParams{
		ProfileName:   "default",
		ManagementURL: "https://mgmt.example.com",
	})

	require.NoError(t, err, "a declined prompt is not an error")
	assert.True(t, outcome.Declined, "nothing was applied")
	assert.Len(t, daemon.requests, 1, "only the refused request")
}

// With no prompt to raise, the refusal is reported as the daemon wrote it, which is
// the guidance that was there before elevation existed.
func TestSetConfigReportsTheRefusalWhenItCannotElevate(t *testing.T) {
	elev := &stubElevator{available: false}
	s, _ := settingsRefusingOnce(t, elev)

	_, err := s.SetConfig(context.Background(), SetConfigParams{
		ProfileName:   "default",
		ManagementURL: "https://mgmt.example.com",
	})

	var clientErr *ClientError
	require.ErrorAs(t, err, &clientErr)
	assert.Equal(t, "privilege_required", clientErr.Code, "error code")
	assert.Contains(t, clientErr.Command, "netbird up -m https://mgmt.example.com",
		"the daemon's own command")
	assert.Empty(t, elev.calls, "no prompt where there is none to raise")
}

// A refusal with nothing in the request the one-shot could apply: the daemon
// cannot see who is calling, and being root would not help either.
func TestSetConfigReportsARefusalWithNothingToElevate(t *testing.T) {
	elev := &stubElevator{available: true}
	s, _ := settingsRefusingOnce(t, elev)

	_, err := s.SetConfig(context.Background(), SetConfigParams{ProfileName: "default"})

	var clientErr *ClientError
	require.ErrorAs(t, err, &clientErr)
	assert.Equal(t, "privilege_required", clientErr.Code, "error code")
	assert.Empty(t, elev.calls, "no prompt")
}
