//go:build !android && !ios && !freebsd && !js

package services

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gcodes "google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
)

func TestErrorClassifier_Classify(t *testing.T) {
	c := errorClassifier{} // nil translator → Short is the bare "error.<code>" key

	t.Run("permission denied by gRPC code with a clean desc", func(t *testing.T) {
		// The daemon now forwards the innermost status: code + clean desc that
		// no longer carries the English "permission denied" marker.
		err := gstatus.Error(gcodes.PermissionDenied, "peer is already registered by a different User or a Setup Key")

		ce := c.classify(err)
		require.NotNil(t, ce)
		require.Equal(t, "permission_denied", ce.Code)
		require.Equal(t, "error.permission_denied", ce.Short)
		require.Equal(t, "peer is already registered by a different User or a Setup Key", ce.Long)
	})

	t.Run("substring match still wins for unclassified codes", func(t *testing.T) {
		err := gstatus.Error(gcodes.Unknown, "peer login has expired")

		ce := c.classify(err)
		require.NotNil(t, ce)
		require.Equal(t, "session_expired", ce.Code)
	})

	t.Run("unavailable code maps to daemon_unreachable", func(t *testing.T) {
		ce := c.classify(gstatus.Error(gcodes.Unavailable, "transport closing"))
		require.Equal(t, "daemon_unreachable", ce.Code)
	})

	t.Run("unmatched stays unknown", func(t *testing.T) {
		ce := c.classify(errors.New("something odd"))
		require.Equal(t, "unknown", ce.Code)
	})

	t.Run("nil error", func(t *testing.T) {
		require.Nil(t, c.classify(nil))
	})
}

// Every reason the daemon explains gets its own code, so the frontend can
// present a held session differently from a privilege refusal instead of both
// landing on the sign-in message.
func TestClassifyMapsEveryDaemonReason(t *testing.T) {
	c := errorClassifier{}

	for _, tc := range []struct {
		name    string
		err     error
		code    string
		command bool
	}{
		{"privilege", ipcauth.PrivilegeError("Claiming a profile requires root.", "sudo netbird profile claim"), "privilege_required", true},
		{"session held", ipcauth.SessionHeldError("switching profile"), "session_held", true},
		{"not owner", ipcauth.NotOwnerError("reading the profile configuration"), "not_profile_owner", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := c.classify(tc.err)
			require.NotNil(t, got)
			assert.Equal(t, tc.code, got.Code)
			assert.NotEmpty(t, got.Long, "the daemon's sentence has to reach the user")
			assert.NotContains(t, got.Long, "rpc error")
			assert.Equal(t, tc.command, got.Command != "")
		})
	}
}

// A reason added daemon-side must still reach the user, losing only the
// tailored presentation.
func TestDenialCodeFallsBackForAnUnknownReason(t *testing.T) {
	assert.Equal(t, "permission_denied", denialCode("SOMETHING_NEW"))
}

// Only a privilege refusal is answered by offering to elevate. Offering it for
// a session another user holds would be nonsense.
func TestPrivilegeRefusedIsNarrow(t *testing.T) {
	assert.True(t, privilegeRefused(ipcauth.PrivilegeError("x", "y")))
	assert.False(t, privilegeRefused(ipcauth.SessionHeldError("connecting")))
	assert.False(t, privilegeRefused(ipcauth.NotOwnerError("connecting")))
	assert.False(t, privilegeRefused(errors.New("connection refused")))
}
