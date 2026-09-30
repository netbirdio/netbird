package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
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

// fakeStream reports err from every call, standing in for a stream the daemon
// opened and then refused.
type fakeStream struct {
	grpc.ClientStream
	err error
}

func (f fakeStream) RecvMsg(any) error            { return f.err }
func (f fakeStream) SendMsg(any) error            { return f.err }
func (f fakeStream) Header() (metadata.MD, error) { return nil, f.err }

// Opening a stream does not wait for the server to accept it, so a refusal
// arrives on the first Recv. capture and expose both read it there.
func TestDenialStreamConvertsRefusalsAfterOpen(t *testing.T) {
	s := denialStream{ClientStream: fakeStream{err: ipcauth.SessionHeldError("starting a packet capture")}}

	for name, err := range map[string]error{
		"RecvMsg": s.RecvMsg(nil),
		"SendMsg": s.SendMsg(nil),
	} {
		t.Run(name, func(t *testing.T) {
			require.Error(t, err)
			assert.NotContains(t, err.Error(), "rpc error", "the envelope must not survive")
			assert.Contains(t, err.Error(), "Starting a packet capture is refused")

			st, ok := gstatus.FromError(err)
			require.True(t, ok, "the code has to survive for callers that branch on it")
			assert.Equal(t, codes.PermissionDenied, st.Code())
		})
	}

	_, err := s.Header()
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "rpc error")
}

// A clean end of stream is not an error. Callers compare against io.EOF, so it
// has to come back as the very same value.
func TestDenialStreamPassesEOFThrough(t *testing.T) {
	s := denialStream{ClientStream: fakeStream{err: io.EOF}}

	assert.Same(t, io.EOF, s.RecvMsg(nil))
	assert.True(t, errors.Is(s.RecvMsg(nil), io.EOF))
}

func TestDenialStreamLeavesOtherErrorsAlone(t *testing.T) {
	plain := errors.New("transport closing")
	s := denialStream{ClientStream: fakeStream{err: plain}}

	assert.Same(t, plain, s.RecvMsg(nil))
}

// captureLog points the standard logger at a buffer for the duration of a test,
// standing in for the console writer every interactive command installs.
func captureLog(t *testing.T, level log.Level) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	logger := log.StandardLogger()
	prevOut, prevLevel, prevFmt := logger.Out, logger.Level, logger.Formatter
	logger.SetOutput(&buf)
	logger.SetLevel(level)
	// The default formatter escapes the quotes inside a message, which would let
	// a logged error slip past a comparison against the error's own text.
	logger.SetFormatter(&log.TextFormatter{DisableQuote: true, DisableTimestamp: true})
	t.Cleanup(func() {
		logger.SetOutput(prevOut)
		logger.SetLevel(prevLevel)
		logger.SetFormatter(prevFmt)
	})
	return &buf
}

// Console logging and PrintErrln both write to os.Stderr, so a command that logs
// the error it is about to return has it printed twice: once by the logger and
// once by Execute. SilenceErrors does not cover this, it only retires cobra's
// own copy.
func TestCommandDoesNotLogTheErrorItReturns(t *testing.T) {
	logged := captureLog(t, log.InfoLevel)

	prev := logLevel
	logLevel = "bogus"
	t.Cleanup(func() { logLevel = prev })

	err := downCmd.RunE(downCmd, nil)
	require.Error(t, err, "an unparseable log level fails before the command dials")
	assert.NotContains(t, logged.String(), err.Error(), "Execute renders this error, so the command must not log it")

	assert.Contains(t, printed(t, err), "not a valid logrus Level", "and it is still reported once")
}

// The rendered sentence drops the envelope and code on purpose, so the raw error
// stays available to a bug report at debug level, below what a user sees.
func TestPrintCommandErrorKeepsTheRawErrorAtDebug(t *testing.T) {
	logged := captureLog(t, log.DebugLevel)

	out := printed(t, ipcauth.SessionHeldError("disconnecting"))

	assert.NotContains(t, out, "rpc error", "the user still reads the sentence alone")
	assert.Contains(t, logged.String(), "rpc error", "the envelope a bug report needs survives in the log")
	assert.Contains(t, logged.String(), "PermissionDenied")
}

// At the level an interactive command actually runs at, the diagnostic stays out
// of the way, so the failure reaches the terminal exactly once.
func TestPrintCommandErrorLogsNothingAtInfo(t *testing.T) {
	logged := captureLog(t, log.InfoLevel)

	printed(t, errors.New("connection refused"))

	assert.NotContains(t, logged.String(), "connection refused")
}
