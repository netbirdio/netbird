package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
)

func printed(t *testing.T, err error) string {
	t.Helper()
	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetErr(&buf)
	printCommandError(cmd, err)
	return buf.String()
}

// The daemon writes these sentences for the user, so they must reach the
// terminal as written rather than inside "rpc error: code = ... desc = ...".
func TestPrintCommandErrorStripsTheGRPCEnvelope(t *testing.T) {
	out := printed(t, ipcauth.SessionHeldError("disconnecting"))

	assert.Contains(t, out, "Disconnecting is refused while another user has this machine connected.")
	assert.Contains(t, out, "netbird down", "the remedy is shown")
	assert.NotContains(t, out, "rpc error")
	assert.NotContains(t, out, "PermissionDenied")
	assert.NotContains(t, out, "Error:", "guidance stands on its own")
}

// A command that adds context still renders, since the status survives wrapping
// and that is what the backoff loops in up and login read.
func TestPrintCommandErrorSeesThroughWrapping(t *testing.T) {
	wrapped := daemonCallError("call service down method", ipcauth.SessionHeldError("disconnecting"))

	st, ok := gstatus.FromError(wrapped)
	require.True(t, ok, "wrapping must not hide the status from code checks")
	assert.Equal(t, codes.PermissionDenied, st.Code())

	out := printed(t, wrapped)
	assert.NotContains(t, out, "rpc error")
	assert.NotContains(t, out, "call service down method")
}

func TestPrintCommandErrorKeepsOrdinaryErrors(t *testing.T) {
	out := printed(t, errors.New("connection refused"))
	assert.Contains(t, out, "Error:")
	assert.Contains(t, out, "connection refused")
}

// A status with no daemon detail is not ours to reword.
func TestPrintCommandErrorLeavesForeignStatusAlone(t *testing.T) {
	out := printed(t, gstatus.Error(codes.Unavailable, "daemon not initialized"))
	assert.Contains(t, out, "Error:")
	assert.Contains(t, out, "daemon not initialized")
}

func TestPrintCommandErrorRendersEveryDaemonReason(t *testing.T) {
	for name, err := range map[string]error{
		"privilege": ipcauth.PrivilegeError("Claiming a profile requires root.", "sudo netbird profile claim"),
		"session":   ipcauth.SessionHeldError("connecting"),
		"ownership": ipcauth.NotOwnerError("switching profile"),
	} {
		t.Run(name, func(t *testing.T) {
			out := printed(t, err)
			assert.NotContains(t, out, "rpc error", fmt.Sprintf("%s refusal still shows the envelope", name))
			assert.NotContains(t, out, "Error:")
		})
	}
}

// The interceptor is what makes this general: once a refusal leaves the daemon
// it reads correctly however a command wraps it, including with %v, which
// breaks the chain every other approach relies on.
func TestDaemonDenialSurvivesAnyWrapping(t *testing.T) {
	denial := asDaemonDenial(ipcauth.SessionHeldError("switching profile"))

	for name, wrapped := range map[string]error{
		"unwrapped":    denial,
		"wrapped once": fmt.Errorf("switch profile: %w", denial),
		"wrapped twice": fmt.Errorf("switch profile: %w",
			fmt.Errorf("switch profile failed: %w", denial)),
		"wrapped with %v": fmt.Errorf("switch profile: %v", denial),
	} {
		t.Run(name, func(t *testing.T) {
			out := printed(t, wrapped)
			assert.NotContains(t, out, "rpc error", "the envelope must never reach the terminal")
			assert.NotContains(t, out, "PermissionDenied")
			assert.Contains(t, out, "Switching profile is refused")
			assert.Contains(t, out, "netbird down")
		})
	}
}

// Re-presenting the error must not cost the code the backoff loops read.
func TestDaemonDenialKeepsItsStatus(t *testing.T) {
	denial := asDaemonDenial(ipcauth.SessionHeldError("connecting"))

	st, ok := gstatus.FromError(denial)
	require.True(t, ok)
	assert.Equal(t, codes.PermissionDenied, st.Code())

	st, ok = gstatus.FromError(fmt.Errorf("up failed: %w", denial))
	require.True(t, ok, "a %w wrap must still expose the code")
	assert.Equal(t, codes.PermissionDenied, st.Code())
}

// Anything that is not a daemon refusal is left exactly as it was.
func TestAsDaemonDenialLeavesOtherErrorsAlone(t *testing.T) {
	plain := errors.New("connection refused")
	assert.Same(t, plain, asDaemonDenial(plain))

	foreign := gstatus.Error(codes.Unavailable, "daemon not initialized")
	assert.Equal(t, foreign, asDaemonDenial(foreign))
	assert.Nil(t, asDaemonDenial(nil))
}
