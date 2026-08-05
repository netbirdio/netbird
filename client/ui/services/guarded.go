//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/elevate"
	"github.com/netbirdio/netbird/client/internal/ipcauth"
)

// The command line of the one-shot mode this binary runs itself in, elevated, to
// apply a setting the daemon restricts to root/administrator. The setting flags
// spell the same words as `netbird up`, so the command a user is shown and what
// runs behind the prompt read alike. Parsed in oneshot.go.
const (
	FlagApplyPrivilegedSettings = "apply-privileged-settings"
	FlagDaemonAddr              = "daemon-addr"
	FlagProfile                 = "profile"
	FlagUser                    = "user"
	FlagLogLevel                = "log-level"
	FlagManagementURL           = "management-url"
	FlagAllowServerSSH          = "allow-server-ssh"
	FlagEnableSSHRoot           = "enable-ssh-root"
	FlagDisableSSHAuth          = "disable-ssh-auth"
)

// Error codes for the ways asking for privileges can fail.
const (
	CodeElevationUnavailable = "elevation_unavailable"
	CodeElevationFailed      = "elevation_failed"
)

// elevationTimeout bounds the wait for a prompt and the change behind it, so a
// dialog nobody answers does not leave its control disabled for the session. Long
// enough to find a password manager, and no shorter than the platforms' own prompt
// timeouts: Windows gives up on its consent dialog after two minutes by itself.
//
// It always ends our waiting, and not always the prompt: Security.framework offers
// no way to withdraw a request, so on macOS the system's own timeout is what closes
// the dialog.
const elevationTimeout = 5 * time.Minute

// elevator raises the platform's privilege prompt and runs the change behind it.
// An interface so tests can answer without a prompt.
type elevator interface {
	// Run runs this binary again, elevated, with the given arguments.
	Run(ctx context.Context, args ...string) error
	// Available reports whether there is a prompt to raise on this host at all.
	Available() bool
}

// osElevator is the real thing: see the elevate package.
type osElevator struct{}

func (osElevator) Run(ctx context.Context, args ...string) error {
	return elevate.Run(ctx, args...)
}

func (osElevator) Available() bool {
	return elevate.Available()
}

// SaveOutcome reports what became of a change that needed authorization.
//
// A declined prompt is a result, not an error: the user was asked and said no, so
// nothing was applied and nothing went wrong. Reporting it as an error would have
// every cancelled prompt logged as one.
type SaveOutcome struct {
	// Declined is set when the user dismissed the authorization prompt, or was
	// refused by policy. Nothing was changed.
	Declined bool `json:"declined"`
}

// GuardedSettings is the subset of the config the daemon restricts to
// root/administrator. Only the fields that are set are changed: a nil pointer, or
// an empty management URL, leaves that setting alone.
//
// The management URL is in here because pointing a host with the SSH server
// running at another management identity hands the decision of who may open a
// shell on it to whoever runs that server, which is the same power as enabling
// the SSH server in the first place.
type GuardedSettings struct {
	ProfileName      string `json:"profileName"`
	Username         string `json:"username"`
	ManagementURL    string `json:"managementUrl,omitempty"`
	ServerSSHAllowed *bool  `json:"serverSshAllowed,omitempty"`
	EnableSSHRoot    *bool  `json:"enableSshRoot,omitempty"`
	DisableSSHAuth   *bool  `json:"disableSshAuth,omitempty"`
}

// guardedSetting is one setting to change, in the two spellings this needs: the
// one-shot's own flag, and the `netbird up` flag that does the same thing from a
// terminal, for when there is no prompt to raise.
type guardedSetting struct {
	arg  string
	flag string
}

// SetGuardedSettings applies settings the daemon refuses from an unprivileged
// caller, by having the operating system run this binary again, elevated, to send
// the same request the frontend would have sent itself.
//
// The user authorizes it at the platform's own prompt: the UAC consent dialog,
// the macOS authentication dialog, or the polkit agent's. Any credentials are the
// operating system's business; NetBird neither sees nor asks for them. Nothing
// about the daemon's rules changes, and the elevated process is authorized like
// any other privileged caller, from the identity the kernel reports for it.
//
// A declined prompt comes back as SaveOutcome.Declined with no error. When there is
// no prompt to raise, or the elevated run failed, the error carries the command
// that does the same thing from a terminal.
func (s *Settings) SetGuardedSettings(ctx context.Context, p GuardedSettings) (SaveOutcome, error) {
	settings := guardedSettings(p)
	if len(settings) == 0 {
		return SaveOutcome{}, &ClientError{
			Code:  CodeElevationFailed,
			Short: "no setting to apply",
			Long:  "no setting to apply",
		}
	}

	args := append([]string{
		"--" + FlagApplyPrivilegedSettings,
		"--" + FlagDaemonAddr, s.daemonAddr,
		"--" + FlagProfile, p.ProfileName,
		"--" + FlagUser, p.Username,
	}, oneShotArgs(settings)...)

	ctx, cancel := context.WithTimeout(ctx, elevationTimeout)
	defer cancel()

	// These changes hand out shells on this host, so both ends are logged: when the
	// prompt went up, and what came of it. It is also the only account of a prompt
	// that was slow to appear or never answered.
	log.Infof("asking for privileges to apply %s", guardedSummary(p))

	if err := s.elevator.Run(ctx, args...); err != nil {
		return s.elevationOutcome(err, p)
	}

	log.Infof("applied %s with the privileges the user authorized", guardedSummary(p))
	return SaveOutcome{}, nil
}

// elevationOutcome sorts what came back into the one normal ending and the two
// that need reporting, with the command that does the same thing by hand.
func (s *Settings) elevationOutcome(err error, p GuardedSettings) (SaveOutcome, error) {
	switch {
	case errors.Is(err, elevate.ErrDeclined):
		// With the reason: an account that may not elevate at all lands here too,
		// and the log is the only place that says which it was.
		log.Infof("the elevation prompt for %s was declined: %v", guardedSummary(p), err)
		return SaveOutcome{Declined: true}, nil
	case errors.Is(err, elevate.ErrUnavailable):
		log.Warnf("cannot ask for privileges to apply %s: %v", guardedSummary(p), err)
		return SaveOutcome{}, &ClientError{
			Code:    CodeElevationUnavailable,
			Short:   s.classifier.translateShort(CodeElevationUnavailable),
			Long:    err.Error(),
			Command: guardedCommand(p),
		}
	default:
		log.Errorf("applying %s with elevated privileges failed: %v", guardedSummary(p), err)
		return SaveOutcome{}, &ClientError{
			Code:    CodeElevationFailed,
			Short:   s.classifier.translateShort(CodeElevationFailed),
			Long:    err.Error(),
			Command: guardedCommand(p),
		}
	}
}

// guardedSettings renders the settings that are actually being changed, from the
// same table the one-shot parses them with: see oneshot.go.
func guardedSettings(p GuardedSettings) []guardedSetting {
	var settings []guardedSetting
	for _, field := range guardedFields {
		value, ok := field.read(p)
		if !ok {
			continue
		}
		settings = append(settings, guardedSetting{
			arg:  "--" + field.flag + "=" + value,
			flag: field.up(value),
		})
	}
	return settings
}

func oneShotArgs(settings []guardedSetting) []string {
	args := make([]string, 0, len(settings))
	for _, setting := range settings {
		args = append(args, setting.arg)
	}
	return args
}

func upFlags(settings []guardedSetting) []string {
	flags := make([]string, 0, len(settings))
	for _, setting := range settings {
		flags = append(flags, setting.flag)
	}
	return flags
}

// guardedCommand is the elevated command line equivalent to the requested
// change, the same shape the daemon names in its own refusals.
func guardedCommand(p GuardedSettings) string {
	settings := guardedSettings(p)
	if len(settings) == 0 {
		return ""
	}
	return ipcauth.UpCommand(strings.Join(upFlags(settings), " "))
}

// guardedSummary names the change for the log.
func guardedSummary(p GuardedSettings) string {
	return fmt.Sprintf("%v for profile %q", oneShotArgs(guardedSettings(p)), p.ProfileName)
}
