//go:build linux

package elevate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// pkexec exit codes that are about the authorization rather than about the program
// we asked it to run. The manual page reserves both.
const (
	// exitDismissed is returned when the user dismissed the authentication
	// dialog.
	exitDismissed = 126
	// exitNotAuthorized is returned when the authorization was not obtained. That
	// covers the user saying no as well as pkexec having had nobody to ask: see
	// noAgentMarkers.
	exitNotAuthorized = 127
)

// exitNotAuthorized covers three different endings that only pkexec's own words
// tell apart, so they are matched here. Read with LC_ALL=C so the words are the
// ones written below.
//
// refusedMarker is a refusal: the user said no, gave up on the password, or holds
// an account that may not elevate at all.
const refusedMarker = "Not authorized"

// noAgentMarkers say pkexec had no way to ask: no agent registered for the
// session, and no controlling terminal for the textual agent it falls back to.
var noAgentMarkers = []string{"authentication agent", "controlling terminal"}

// run asks polkit to run self as root. pkexec hands the request to the session's
// polkit agent, which is what prompts and what collects any password; we see only
// its verdict.
//
// The environment is otherwise deliberately not passed through: pkexec clears it
// bar a small allowlist, and the one-shot needs nothing from it.
func run(ctx context.Context, self string, args []string) error {
	pkexec, err := exec.LookPath("pkexec")
	if err != nil {
		return fmt.Errorf("%w: pkexec is not installed", ErrUnavailable)
	}

	cmd := exec.CommandContext(ctx, pkexec, append([]string{self}, args...)...)
	// C locale so pkexec's own diagnostics are the ones noAgentMarkers knows.
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	// The one-shot reports itself on stdout for macOS's sake, where there is no
	// exit status to read. Here there is one, so that line is noise.
	cmd.Stdout = io.Discard

	err = cmd.Run()
	if err == nil {
		return nil
	}

	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return fmt.Errorf("run pkexec: %w", err)
	}

	// Matched against everything pkexec said, reported as one line: a complaint
	// that is not the first thing printed still has to be recognised, and reading
	// it as a refusal would swallow it.
	full := stderr.String()
	out := firstLine(full)

	switch exitErr.ExitCode() {
	case exitDismissed:
		return ErrDeclined
	case exitNotAuthorized:
		return notAuthorized(full, out)
	default:
		return fmt.Errorf("elevated netbird exited with %d: %s", exitErr.ExitCode(), out)
	}
}

// notAuthorized sorts out the three endings pkexec reports as exitNotAuthorized.
//
// It also returns that code when the authorization succeeded and it then could
// not run the program, so a refusal has to be recognised rather than assumed:
// reading every one of these as "the user said no" would revert the control in
// silence on a host where elevation is broken.
func notAuthorized(full, out string) error {
	switch {
	case hasAny(full, noAgentMarkers):
		return fmt.Errorf("%w: polkit had no way to ask: %s", ErrUnavailable, out)
	case out == noOutput, strings.Contains(full, refusedMarker):
		// The user said no, which needs no message; that an account barred from
		// elevating altogether lands here too is why the reason is kept.
		return fmt.Errorf("%w: %s", ErrDeclined, out)
	default:
		return fmt.Errorf("pkexec could not run elevated netbird: %s", out)
	}
}

func hasAny(s string, markers []string) bool {
	for _, marker := range markers {
		if strings.Contains(s, marker) {
			return true
		}
	}
	return false
}

func mechanismAvailable() bool {
	_, err := exec.LookPath("pkexec")
	return err == nil
}
