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

const notOwnerSummaryText = "Reading the profile configuration is refused because the profile it addresses belongs to another user."

// stubConfigDaemon refuses GetConfig the way the daemon refuses a caller who
// does not own the profile the request names. The embedded interface is nil, so
// any other call panics rather than passing quietly.
type stubConfigDaemon struct {
	proto.DaemonServiceClient
	err error
}

func (d *stubConfigDaemon) GetConfig(_ context.Context, _ *proto.GetConfigRequest, _ ...grpc.CallOption) (*proto.GetConfigResponse, error) {
	return nil, d.err
}

// notOwnerRefusal is the error the gate raises for a profile owned by somebody
// else: see ipcauth.NotOwnerError. It carries no command on purpose — privilege
// is not what the method asked for.
func notOwnerRefusal(t *testing.T) error {
	t.Helper()

	st, err := gstatus.New(codes.PermissionDenied, notOwnerSummaryText).
		WithDetails(&errdetails.ErrorInfo{
			Reason:   ipcauth.ErrorReasonNotProfileOwner,
			Domain:   ipcauth.ErrorDomain,
			Metadata: map[string]string{ipcauth.ErrorMetaSummary: notOwnerSummaryText},
		})
	require.NoError(t, err, "build the refusal detail")
	return st.Err()
}

// The settings screen reads the config on mount and shows whatever comes back,
// so an unclassified refusal there is a raw gRPC dump in front of the user.
func TestSettingsGetConfigClassifiesRefusal(t *testing.T) {
	// nil translator → Short is the bare "error.<code>" key.
	settings := NewSettings(stubConn{client: &stubConfigDaemon{err: notOwnerRefusal(t)}}, nil, nil, testDaemonAddr)

	_, err := settings.GetConfig(context.Background(), ConfigParams{ProfileName: "01HZY0000000000000000000"})

	clientErr, ok := err.(*ClientError)
	require.True(t, ok, "GetConfig must return the classified error, got %T", err)
	assert.Equal(t, "not_profile_owner", clientErr.Code, "the refusal reason decides the code")
	assert.Equal(t, notOwnerSummaryText, clientErr.Long, "the daemon's sentence is the detail")
	assert.Empty(t, clientErr.Command, "this refusal has no command to offer")
}
