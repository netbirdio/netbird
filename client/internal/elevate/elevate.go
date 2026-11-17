// Package elevate re-runs this very executable under the operating system's own
// privilege-elevation mechanism and waits for it to finish.
//
// It exists so that a change the daemon restricts to root/administrator can be
// authorized from the GUI, by the user, at the moment they ask for it: Windows
// shows the UAC consent dialog, macOS the system authentication dialog, and
// Linux/FreeBSD the session's polkit agent. The credentials, where any are
// asked for, are collected by the operating system and never pass through
// NetBird.
//
// What the elevated process then does is the caller's business: it is the same
// binary, in a one-shot mode, and it is authorized by the daemon exactly like
// any other privileged caller, from the identity the kernel reports on the
// control channel. Nothing here grants privilege, and the daemon gains no new
// way to be talked into something: elevation only changes who is calling it.
package elevate

import (
	"context"
	"errors"

	log "github.com/sirupsen/logrus"
)

// AppliedMarker is what the elevated process prints on standard output once it has
// done what it was run for.
//
// macOS's AuthorizationExecuteWithPrivileges reports no exit status and does not
// say which process it started, so there this line is the only evidence that the
// change was applied. The other platforms have an exit code and ignore it.
const AppliedMarker = "netbird-elevated: applied"

var (
	// ErrDeclined reports that the user dismissed the prompt or did not
	// authenticate. Nothing happened and nothing is wrong: a caller undoes its
	// optimistic update and stays quiet.
	ErrDeclined = errors.New("authorization declined")

	// ErrUnavailable reports that this host has no elevation mechanism we can
	// drive: no polkit on a Unix desktop, or an executable we decline to run as
	// root. A caller falls back to telling the user which command to run.
	ErrUnavailable = errors.New("no privilege elevation mechanism available")
)

// Run runs this executable with args under the platform's elevation mechanism
// and waits for it to exit. A non-zero exit is returned as an error, so the
// caller can treat a completed Run as the operation having succeeded.
//
// The args are the caller's own command line, so they cross no privilege
// boundary: only a user who has just authenticated as an administrator can get
// them run at all.
func Run(ctx context.Context, args ...string) error {
	self, err := trustedSelf()
	if err != nil {
		return err
	}
	return run(ctx, self, args)
}

// Available reports whether Run has a mechanism to use on this host, so a caller
// can offer the prompt only when there is one and otherwise fall back to
// guidance the user can act on. It answers from what is installed, not from what
// the user is allowed to do: an administrator's password may still be required
// and may still not be given, which is ErrDeclined from Run.
func Available() bool {
	if _, err := trustedSelf(); err != nil {
		// Worth a line: this is also what a build run from a group-writable
		// directory hits, and there is nothing in the UI to say why the offer is
		// missing.
		log.Debugf("not offering privilege elevation: %v", err)
		return false
	}
	return mechanismAvailable()
}
