//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"

	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/elevate"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/util"
)

// The other end of SetGuardedSettings: the mode this binary runs itself in,
// elevated, to apply the settings the daemon restricts to root/administrator.
//
// Both ends are here on purpose. What may be changed this way is an allowlist, and
// an allowlist declared twice is one that will eventually disagree with itself, so
// the arguments are rendered and parsed from a single table: guardedFields. Adding
// a setting is one row; nothing generic passes through, and no field outside the
// table can be reached with an elevated request no matter what lands on the command
// line.

// oneShotTimeout bounds the whole one-shot: connect, one RPC, exit. Generous
// because the user has just waited for an authentication dialog, and a failure here
// costs them the entire round trip.
const oneShotTimeout = 30 * time.Second

// Exit codes the parent reads where the platform gives it one.
const (
	exitOK      = 0
	exitFailure = 1
	exitUsage   = 2
)

// guardedField is one setting the one-shot understands, in the two spellings it
// needs and with the two halves of its plumbing.
type guardedField struct {
	// flag names it on the one-shot's command line.
	flag  string
	usage string
	// read returns the value to send and whether the caller asked for this setting
	// at all.
	read func(GuardedSettings) (string, bool)
	// write parses a value from the command line onto the request. It is the only
	// thing that validates the value, so it fails on anything it does not
	// recognise rather than guessing.
	write func(*proto.SetConfigRequest, string) error
	// up renders the equivalent `netbird up` flag, for the fallback command shown
	// when there is no prompt to raise.
	up func(value string) string
}

var guardedFields = []guardedField{
	{
		flag:  FlagManagementURL,
		usage: "Management server the profile registers with.",
		read:  func(p GuardedSettings) (string, bool) { return p.ManagementURL, p.ManagementURL != "" },
		write: func(req *proto.SetConfigRequest, value string) error {
			// Parsed with the config layer's own parser, so what the elevated run
			// accepts cannot drift from what the daemon would store.
			if _, err := profilemanager.ParseServiceURL("Management URL", value); err != nil {
				return err
			}
			req.ManagementUrl = value
			return nil
		},
		// The daemon names this one as `-m <url>` in its own refusals.
		up: func(value string) string { return "-m " + value },
	},
	boolField(FlagAllowServerSSH, "Run the NetBird SSH server.",
		func(p GuardedSettings) *bool { return p.ServerSSHAllowed },
		func(req *proto.SetConfigRequest, v *bool) { req.ServerSSHAllowed = v }),
	boolField(FlagEnableSSHRoot, "Allow SSH sessions to privileged accounts.",
		func(p GuardedSettings) *bool { return p.EnableSSHRoot },
		func(req *proto.SetConfigRequest, v *bool) { req.EnableSSHRoot = v }),
	boolField(FlagDisableSSHAuth, "Accept SSH sessions without authentication.",
		func(p GuardedSettings) *bool { return p.DisableSSHAuth },
		func(req *proto.SetConfigRequest, v *bool) { req.DisableSSHAuth = v }),
}

// fieldValue is a flag that remembers whether it was given, and requires a value:
// the renderer always writes one, so a bare flag is a caller that got it wrong.
type fieldValue struct {
	set   bool
	value string
}

func (v *fieldValue) String() string {
	if v == nil {
		return ""
	}
	return v.value
}

func (v *fieldValue) Set(value string) error {
	v.set, v.value = true, value
	return nil
}

// boolField describes a setting that is on or off. The value is always spelled out,
// so that turning a setting off is as unambiguous as turning it on and a flag with
// no value is a mistake rather than an "on".
func boolField(
	name, usage string,
	read func(GuardedSettings) *bool,
	write func(*proto.SetConfigRequest, *bool),
) guardedField {
	return guardedField{
		flag:  name,
		usage: usage,
		read: func(p GuardedSettings) (string, bool) {
			value := read(p)
			if value == nil {
				return "", false
			}
			return strconv.FormatBool(*value), true
		},
		write: func(req *proto.SetConfigRequest, value string) error {
			parsed, err := strconv.ParseBool(value)
			if err != nil {
				return fmt.Errorf("parse %q as a boolean: %w", value, err)
			}
			write(req, &parsed)
			return nil
		},
		up: func(value string) string { return "--" + name + "=" + value },
	}
}

// IsPrivilegedSettingsRun reports whether this process was started as the one-shot.
// The flag is a marker rather than a value, so only the bare forms count: reading a
// value would mean "--flag=false" started it too.
func IsPrivilegedSettingsRun(args []string) bool {
	for _, arg := range args {
		if arg == "--"+FlagApplyPrivilegedSettings || arg == "-"+FlagApplyPrivilegedSettings {
			return true
		}
	}
	return false
}

// RunPrivilegedSettings applies the requested settings and returns the process exit
// code. connect dials the daemon, which is the caller's business because only it
// knows how this build talks to it.
//
// Everything it reports goes to stderr, which is what the parent captures where the
// platform lets it. On success it says so on standard output, because macOS gives
// the parent no exit status to read: see elevate.AppliedMarker.
func RunPrivilegedSettings(args []string, connect func(addr string) (proto.DaemonServiceClient, error)) int {
	fs := flag.NewFlagSet("netbird-ui --"+FlagApplyPrivilegedSettings, flag.ContinueOnError)
	fs.Bool(FlagApplyPrivilegedSettings, false, "Apply the settings the daemon restricts to root/administrator and exit.")
	daemonAddr := fs.String(FlagDaemonAddr, "", "Daemon gRPC address: unix:///path, npipe://name or tcp://host:port")
	logLevel := fs.String(FlagLogLevel, "info", "Log level: trace|debug|info|warn|error.")
	profile := fs.String(FlagProfile, "", "Profile to change.")
	username := fs.String(FlagUser, "", "Owner of the profile.")

	values := make([]fieldValue, len(guardedFields))
	for i, field := range guardedFields {
		fs.Var(&values[i], field.flag, field.usage)
	}

	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	if err := util.InitLog(*logLevel, "console"); err != nil {
		fmt.Fprintf(os.Stderr, "init log: %v\n", err)
		return exitFailure
	}

	req, err := privilegedRequest(*profile, *username, values)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return exitUsage
	}

	ctx, cancel := context.WithTimeout(context.Background(), oneShotTimeout)
	defer cancel()

	if err := applyPrivilegedSettings(ctx, *daemonAddr, req, connect); err != nil {
		fmt.Fprintf(os.Stderr, "apply settings: %v\n", err)
		return exitFailure
	}

	fmt.Fprintln(os.Stdout, elevate.AppliedMarker)
	return exitOK
}

// privilegedRequest builds the request from the flags that were given, and refuses
// one that asks for nothing.
func privilegedRequest(profile, username string, values []fieldValue) (*proto.SetConfigRequest, error) {
	req := &proto.SetConfigRequest{ProfileName: profile, Username: username}

	given := 0
	for i, field := range guardedFields {
		if !values[i].set {
			continue
		}
		if err := field.write(req, values[i].value); err != nil {
			return nil, fmt.Errorf("--%s: %w", field.flag, err)
		}
		given++
	}
	if given == 0 {
		return nil, errors.New("no setting to apply")
	}
	return req, nil
}

func applyPrivilegedSettings(
	ctx context.Context,
	daemonAddr string,
	req *proto.SetConfigRequest,
	connect func(addr string) (proto.DaemonServiceClient, error),
) error {
	client, err := connect(daemonAddr)
	if err != nil {
		return err
	}
	if _, err := client.SetConfig(ctx, req); err != nil {
		// Unwrapped: the daemon's message is written for a person, and a refusal
		// elevation cannot fix has to say so where the parent can read it off
		// stderr.
		return errors.New(gstatus.Convert(err).Message())
	}
	return nil
}

// interface guard: the one-shot's flags are flag.Value.
var _ flag.Value = (*fieldValue)(nil)
