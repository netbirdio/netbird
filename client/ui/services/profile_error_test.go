//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
	"github.com/netbirdio/netbird/client/proto"
)

// stubProfileDaemon refuses SwitchProfile the way the daemon refuses a caller
// who does not hold the session. The embedded interface is nil, so any other
// call panics rather than passing quietly.
type stubProfileDaemon struct {
	proto.DaemonServiceClient
	err error
}

func (d *stubProfileDaemon) SwitchProfile(_ context.Context, _ *proto.SwitchProfileRequest, _ ...grpc.CallOption) (*proto.SwitchProfileResponse, error) {
	return nil, d.err
}

// sessionHeldRefusal is the error the daemon raises when another user holds the
// connection, detail and all: see ipcauth.SessionHeldError.
func sessionHeldRefusal(t *testing.T) error {
	t.Helper()

	st, err := gstatus.New(codes.PermissionDenied, sessionHeldSummaryText+"\n\nsudo netbird down").
		WithDetails(&errdetails.ErrorInfo{
			Reason: ipcauth.ErrorReasonSessionHeld,
			Domain: ipcauth.ErrorDomain,
			Metadata: map[string]string{
				ipcauth.ErrorMetaSummary: sessionHeldSummaryText,
				ipcauth.ErrorMetaCommand: "sudo netbird down",
			},
		})
	require.NoError(t, err, "build the refusal detail")
	return st.Err()
}

const sessionHeldSummaryText = "Switching profiles is refused while another user has this machine connected."

func profilesRefusingSwitch(t *testing.T) *Profiles {
	t.Helper()
	// nil translator → Short is the bare "error.<code>" key, which is enough to
	// tell a resolved headline from the daemon's own sentence.
	return NewProfiles(stubConn{client: &stubProfileDaemon{err: sessionHeldRefusal(t)}}, nil, nil)
}

// A refused switch has to reach the caller as the classified value, since that is
// the only thing carrying the headline and the command the frontend renders.
func TestProfilesSwitchClassifiesRefusal(t *testing.T) {
	_, err := profilesRefusingSwitch(t).Switch(context.Background(), ProfileRef{ProfileName: "work"})

	clientErr, ok := err.(*ClientError)
	require.True(t, ok, "Switch must return the classified error, got %T", err)
	assert.Equal(t, "session_held", clientErr.Code, "the refusal reason decides the code")
	assert.Equal(t, sessionHeldSummaryText, clientErr.Long, "the daemon's sentence is the detail")
	assert.Equal(t, "sudo netbird down", clientErr.Command, "the suggested command survives")
}

// The switcher used to wrap this in fmt.Errorf, which left the Wails binding
// nothing to marshal and put the raw "switch profile %q: rpc error: ..." string
// in front of the user instead of the headline and the copyable command.
func TestProfileSwitcherReturnsClassifiedRefusal(t *testing.T) {
	switcher := NewProfileSwitcher(profilesRefusingSwitch(t), nil, nil)

	err := switcher.SwitchActive(context.Background(), ProfileRef{ProfileName: "01HZY0000000000000000000"})

	clientErr, ok := err.(*ClientError)
	require.True(t, ok, "the switcher must pass the classified error through, got %T", err)
	assert.Equal(t, "session_held", clientErr.Code, "the refusal reason decides the code")
	assert.Equal(t, "sudo netbird down", clientErr.Command, "the suggested command survives")
	assert.Equal(t, "error.session_held", err.Error(),
		"no wrapping prefix and no gRPC dump in front of the headline")
}
