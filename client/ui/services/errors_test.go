//go:build !android && !ios && !freebsd && !js

package services

import (
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	gcodes "google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
	"github.com/netbirdio/netbird/client/ui/i18n"
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

	// The OS denial on the socket must not be read as a management sign-in
	// rejection.
	t.Run("socket denial maps to daemon_access_denied", func(t *testing.T) {
		unix := gstatus.Error(gcodes.Unavailable, `connection error: desc = "transport: Error while dialing: dial unix /var/run/netbird.sock: connect: permission denied"`)
		assert.Equal(t, "daemon_access_denied", c.classify(unix).Code, "unix EACCES")

		pipe := gstatus.Error(gcodes.Unavailable, `connection error: desc = "transport: Error while dialing: open \\.\pipe\ProtectedPrefix\Administrators\netbird: Access is denied."`)
		assert.Equal(t, "daemon_access_denied", c.classify(pipe).Code, "windows ERROR_ACCESS_DENIED")
	})

	t.Run("missing socket stays daemon_unreachable", func(t *testing.T) {
		err := gstatus.Error(gcodes.Unavailable, `connection error: desc = "transport: Error while dialing: dial unix /var/run/netbird.sock: connect: no such file or directory"`)
		assert.Equal(t, "daemon_unreachable", c.classify(err).Code, "a stopped daemon is not a denial")
	})

	t.Run("unmatched stays unknown", func(t *testing.T) {
		ce := c.classify(errors.New("something odd"))
		require.Equal(t, "unknown", ce.Code)
	})

	t.Run("nil error", func(t *testing.T) {
		require.Nil(t, c.classify(nil))
	})
}

// Every reason the daemon explains gets its own code, and the headline is looked
// up from that code rather than repeating the daemon's sentence, so a held
// session reads differently from a privilege refusal.
func TestClassifyMapsEveryDaemonReason(t *testing.T) {
	c := errorClassifier{} // nil translator → Short is the bare "error.<code>" key

	for _, tc := range []struct {
		name    string
		err     error
		code    string
		command bool
	}{
		{"privilege", ipcauth.PrivilegeError("Claiming a profile requires root.", "sudo netbird profile claim"), "privilege_required", true},
		{"session held", ipcauth.SessionHeldError("switching profile"), "session_held", true},
		{"not owner", ipcauth.NotOwnerError("reading the profile configuration"), "not_profile_owner", false},
		{"unowned", ipcauth.UnownedError("connecting", "default", false), "profile_unowned", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := c.classify(tc.err)
			require.NotNil(t, got)
			assert.Equal(t, tc.code, got.Code)
			assert.Equal(t, "error."+tc.code, got.Short, "Short comes from the locale bundle, not the daemon")
			assert.NotEmpty(t, got.Long, "the daemon's sentence has to reach the user")
			assert.NotContains(t, got.Long, "rpc error")
			assert.Equal(t, tc.command, got.Command != "")
		})
	}
}

// Every denial code needs an entry in the shipped bundle, or the dialog shows a
// bare "error.<code>" key where the headline should be. Resolved against the real
// locale tree so a reason added without a translation fails here, not on screen.
func TestDenialHeadlinesResolveInTheShippedBundle(t *testing.T) {
	bundle, err := i18n.NewBundle(os.DirFS("../i18n/locales"))
	require.NoError(t, err, "the shipped locale tree must load")

	c := errorClassifier{translator: bundle}

	for _, tc := range []struct {
		name  string
		err   error
		short string
		long  string
	}{
		{
			"privilege",
			ipcauth.PrivilegeError("Claiming a profile requires root.", "sudo netbird profile claim"),
			"This action requires elevated privileges.",
			"Claiming a profile requires root.",
		},
		{
			"session held",
			ipcauth.SessionHeldError("switching profile"),
			"Another user has this machine connected.",
			"Switching profile is refused while another user has this machine connected.",
		},
		{
			"not owner",
			ipcauth.NotOwnerError("reading the profile configuration"),
			"This profile belongs to another user.",
			"Reading the profile configuration is refused because the profile it addresses belongs to another user.",
		},
		{
			"unowned",
			ipcauth.UnownedError("connecting", "default", false),
			"This profile has no owner yet.",
			"Connecting is refused because the profile it addresses has no owner on record.",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := c.classify(tc.err)
			require.NotNil(t, got)
			assert.Equal(t, tc.short, got.Short, "Short should be the localised headline for the code")
			assert.Contains(t, got.Long, tc.long, "Long should carry the daemon's own sentence")
			assert.NotEqual(t, got.Short, got.Long, "a repeated sentence costs the frontend its detail line")
		})
	}
}

// A reason added daemon-side must still reach the user, losing only the tailored
// presentation. It must not borrow another code's headline: "permission_denied"
// is the sign-in rejection, which has nothing to do with an IPC refusal.
func TestClassifyKeepsTheSentenceForAnUnknownReason(t *testing.T) {
	code, known := denialCode("SOMETHING_NEW")
	assert.False(t, known, "an unrecognised reason must not claim a tailored headline")
	assert.Equal(t, "permission_denied", code)

	const summary = "Doing something new is refused for a reason this build predates."
	st, err := gstatus.New(gcodes.PermissionDenied, summary).WithDetails(&errdetails.ErrorInfo{
		Reason:   "SOMETHING_NEW",
		Domain:   ipcauth.ErrorDomain,
		Metadata: map[string]string{ipcauth.ErrorMetaSummary: summary},
	})
	require.NoError(t, err)

	got := errorClassifier{}.classify(st.Err())
	require.NotNil(t, got)
	assert.Equal(t, summary, got.Short, "the daemon's sentence stands in for the headline")
	assert.Equal(t, summary, got.Long)
}

// Only a privilege refusal is answered by offering to elevate. Offering it for
// a session another user holds would be nonsense.
func TestPrivilegeRefusedIsNarrow(t *testing.T) {
	assert.True(t, privilegeRefused(ipcauth.PrivilegeError("x", "y")))
	assert.False(t, privilegeRefused(ipcauth.SessionHeldError("connecting")))
	assert.False(t, privilegeRefused(ipcauth.NotOwnerError("connecting")))
	assert.False(t, privilegeRefused(errors.New("connection refused")))
}
