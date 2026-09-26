package cmd

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"
)

// A refused settings update has to fail `netbird up`, or a caller that asked
// for a setting the daemon will not apply connects as if it had been applied.
// The daemon being unable to serve the call is the case that stays a warning.
func TestRefusedSettingsUpdate(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		wantRefused bool
	}{
		{
			name:        "the kill switch refused the change",
			err:         gstatus.Errorf(codes.FailedPrecondition, "update settings are disabled, you cannot use this feature without update settings enabled"),
			wantRefused: true,
		},
		{
			name:        "an MDM policy manages the field",
			err:         gstatus.Errorf(codes.FailedPrecondition, "fields managed by MDM policy: managementURL"),
			wantRefused: true,
		},
		{
			name:        "the daemon cannot serve the call",
			err:         gstatus.Errorf(codes.Unavailable, "connection refused"),
			wantRefused: false,
		},
		{
			name:        "any other RPC failure",
			err:         gstatus.Errorf(codes.Internal, "boom"),
			wantRefused: false,
		},
		{
			name:        "not a status error at all",
			err:         errors.New("boom"),
			wantRefused: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason, refused := refusedSettingsUpdate(tt.err)
			require.Equal(t, tt.wantRefused, refused)
			if tt.wantRefused {
				require.Equal(t, gstatus.Convert(tt.err).Message(), reason, "the daemon's reason must reach the caller")
			}
		})
	}
}

// Both `netbird up` and `netbird login` drive Login through the backoff cycle,
// and a final answer has to stop it: retrying a refusal only replaces the
// daemon's reason with "login backoff cycle failed" thirty seconds later.
func TestTerminalLoginError(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		wantTerminal bool
	}{
		{name: "settings refused by the kill switch", err: gstatus.Errorf(codes.FailedPrecondition, "update settings are disabled"), wantTerminal: true},
		{name: "field managed by MDM", err: gstatus.Errorf(codes.FailedPrecondition, "fields managed by MDM policy: managementURL"), wantTerminal: true},
		{name: "caller not allowed", err: gstatus.Errorf(codes.PermissionDenied, "nope"), wantTerminal: true},
		{name: "malformed request", err: gstatus.Errorf(codes.InvalidArgument, "nope"), wantTerminal: true},
		{name: "profile not found", err: gstatus.Errorf(codes.NotFound, "nope"), wantTerminal: true},
		{name: "method missing on an older daemon", err: gstatus.Errorf(codes.Unimplemented, "nope"), wantTerminal: true},
		{name: "daemon unreachable, worth retrying", err: gstatus.Errorf(codes.Unavailable, "connection refused"), wantTerminal: false},
		{name: "transient internal failure", err: gstatus.Errorf(codes.Internal, "boom"), wantTerminal: false},
		{name: "not a status error", err: errors.New("boom"), wantTerminal: false},
		{name: "no error at all, the login succeeded", err: nil, wantTerminal: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.wantTerminal, terminalLoginError(tt.err))
		})
	}
}
