//go:build !windows && !js

package certproof

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/certposture"
)

// fakeHelper is a child process that drains its stdin and then prints script's output,
// standing in for a helper running in a user session the daemon cannot trust.
func fakeHelper(t *testing.T, script string) *exec.Cmd {
	t.Helper()
	return exec.Command("/bin/sh", "-c", "cat >/dev/null; "+script)
}

func printJSON(t *testing.T, v any) string {
	t.Helper()
	out, err := json.Marshal(v)
	require.NoError(t, err)
	return fmt.Sprintf("printf '%%s' '%s'", out)
}

func TestRunHelperCmd_KeepsOnlyRequestedProofs(t *testing.T) {
	req := HelperRequest{PeerKey: peerKey, Challenges: []HelperChallenge{{Nonce: []byte("asked")}}}
	resp := HelperResponse{Proofs: []certposture.Proof{
		{Nonce: []byte("injected"), Signature: []byte("x")},
		{Nonce: []byte("asked"), Signature: []byte("first")},
		{Nonce: []byte("asked"), Signature: []byte("second")},
	}}

	proofs, err := runHelperCmd(fakeHelper(t, printJSON(t, resp)), req)

	require.NoError(t, err)
	require.Len(t, proofs, 1, "a helper may not return more proofs than challenges or proofs for nonces it was not asked about")
	assert.Equal(t, []byte("first"), proofs[0].Signature, "the first proof for the requested nonce is kept")
}

func TestRunHelperCmd_RejectsOversizedOutput(t *testing.T) {
	req := HelperRequest{Challenges: []HelperChallenge{{Nonce: []byte("asked")}}}
	script := fmt.Sprintf("head -c %d /dev/zero", maxHelperStdout+1)

	_, err := runHelperCmd(fakeHelper(t, script), req)

	assert.ErrorIs(t, err, errHelperOutputTooLarge)
}

func TestRunHelperCmd_CapsStderrInError(t *testing.T) {
	req := HelperRequest{Challenges: []HelperChallenge{{Nonce: []byte("asked")}}}
	script := fmt.Sprintf("head -c %d /dev/zero | tr '\\0' 'a' >&2; exit 3", 10*maxHelperStderr)

	_, err := runHelperCmd(fakeHelper(t, script), req)

	require.Error(t, err)
	assert.LessOrEqual(t, len(err.Error()), maxHelperStderr+100, "a chatty helper must not blow up the daemon's error or log line")
	assert.True(t, strings.Contains(err.Error(), "exit status 3"), "the exit status is kept: %v", err)
}

func TestRunHelperCmd_ReturnsWhenAGrandchildHoldsTheOutputPipe(t *testing.T) {
	req := HelperRequest{Challenges: []HelperChallenge{{Nonce: []byte("asked")}}}
	resp := HelperResponse{Proofs: []certposture.Proof{{Nonce: []byte("asked"), Signature: []byte("sig")}}}

	// The helper answers and exits, but leaves a background process holding the stdout
	// it inherited. This is what a wedged `netbird posture cert-proof` behind a keychain
	// prompt looks like from here: killing the process we launched does not close the
	// pipe, so the copy out of it never sees EOF.
	script := printJSON(t, resp) + "; sleep 10 &"

	done := make(chan error, 1)
	go func() {
		_, err := runHelperCmd(fakeHelper(t, script), req)
		done <- err
	}()

	select {
	case err := <-done:
		assert.ErrorIs(t, err, exec.ErrWaitDelay, "the output is incomplete, so the run must fail rather than report proofs")
	case <-time.After(5 * time.Second):
		t.Fatal("runHelperCmd never returned while a grandchild held the output pipe, so the collector's busy latch would stay set for the life of the daemon")
	}
}

func TestRunHelperCmd_ReturnsWhenTheDeadlineKillsTheLauncher(t *testing.T) {
	req := HelperRequest{Challenges: []HelperChallenge{{Nonce: []byte("asked")}}}

	// The shape the daemon actually meets on macOS: the process it launches is only a
	// launcher, the work happens in a grandchild, and the deadline reaps the launcher
	// while the grandchild keeps the stdout it inherited open. Unlike the case above
	// the process is killed, so Wait reports that rather than ErrWaitDelay.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", "cat >/dev/null; sleep 10 & sleep 10")

	done := make(chan error, 1)
	go func() {
		proofs, err := runHelperCmd(cmd, req)
		assert.Empty(t, proofs, "a run the deadline cut short has nothing trustworthy to report")
		done <- err
	}()

	select {
	case err := <-done:
		require.Error(t, err, "the run was cut short, so it must not be reported as a success")
	case <-time.After(5 * time.Second):
		t.Fatal("runHelperCmd never returned after the deadline killed the launcher, so the collector's busy latch would stay set for the life of the daemon")
	}
}

func TestRunHelperCmd_RejectsGarbage(t *testing.T) {
	req := HelperRequest{Challenges: []HelperChallenge{{Nonce: []byte("asked")}}}

	_, err := runHelperCmd(fakeHelper(t, "printf 'not json'"), req)

	assert.ErrorContains(t, err, "decode helper response")
}
