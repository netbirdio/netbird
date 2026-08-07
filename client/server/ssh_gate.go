package server

import (
	"context"
	"fmt"
	"net/url"
	"runtime"
	"strings"

	log "github.com/sirupsen/logrus"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/daemonaddr"
	"github.com/netbirdio/netbird/client/internal/ipcauth"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/util"
)

// The daemon runs as root/LocalSystem, so a handful of config changes cross the
// user-to-root boundary and are restricted to privileged callers:
//
//   - Enabling SSH root login, or disabling SSH authentication, turns the
//     daemon's SSH server into a root (or unauthenticated) shell.
//   - Enabling the SSH server at all is what makes the above reachable, and a
//     profile the caller owns is not a privilege they hold.
//   - Enabling the VNC server exposes the console session, which on a
//     multi-user host belongs to another user, and disabling its approval
//     prompt removes that user's only say in it.
//   - While a remote-access server (SSH or VNC) is enabled, repointing the
//     profile at another management identity hands authorization decisions,
//     including which keys and users are accepted, to whoever controls that
//     identity. Changing the management URL and deregistering the peer are both
//     ways to do that.
//
// Everything else stays unauthenticated, so this is not an authorization model:
// it only refuses the changes that would let a local user become root, or reach
// another user's desktop. A caller whose identity cannot be established is
// refused as well.

// privilegedConfigChange is the subset of a config request that crosses the
// user-to-root boundary. Fields are nil or empty when the request leaves them
// untouched.
type privilegedConfigChange struct {
	managementURL      string
	serverSSHAllowed   *bool
	enableSSHRoot      *bool
	disableSSHAuth     *bool
	serverVNCAllowed   *bool
	disableVNCApproval *bool
}

func privilegedChangeFromSetConfig(msg *proto.SetConfigRequest) privilegedConfigChange {
	return privilegedConfigChange{
		managementURL:      msg.GetManagementUrl(),
		serverSSHAllowed:   msg.ServerSSHAllowed,
		enableSSHRoot:      msg.EnableSSHRoot,
		disableSSHAuth:     msg.DisableSSHAuth,
		serverVNCAllowed:   msg.ServerVNCAllowed,
		disableVNCApproval: msg.DisableVNCApproval,
	}
}

func privilegedChangeFromLogin(msg *proto.LoginRequest) privilegedConfigChange {
	return privilegedConfigChange{
		managementURL:      msg.GetManagementUrl(),
		serverSSHAllowed:   msg.ServerSSHAllowed,
		enableSSHRoot:      msg.EnableSSHRoot,
		disableSSHAuth:     msg.DisableSSHAuth,
		serverVNCAllowed:   msg.ServerVNCAllowed,
		disableVNCApproval: msg.DisableVNCApproval,
	}
}

// requirePrivilegeForConfigChange refuses the privileged parts of a config
// change when the caller is not root/administrator. stored is the profile's
// current config, or nil when it has none yet.
//
// Each check compares against the stored value so that a request restating a
// value it does not change is never refused: a UI that submits the whole
// settings form must not start failing once an administrator has enabled SSH.
func requirePrivilegeForConfigChange(ctx context.Context, stored *profilemanager.Config, change privilegedConfigChange) error {
	if enables(storedFlag(stored, func(c *profilemanager.Config) *bool { return c.EnableSSHRoot }), change.enableSSHRoot) {
		return denyPrivileged(ctx, "enabling SSH root login", ipcauth.UpCommand("--enable-ssh-root"))
	}

	if enables(storedFlag(stored, func(c *profilemanager.Config) *bool { return c.DisableSSHAuth }), change.disableSSHAuth) {
		return denyPrivileged(ctx, "disabling SSH authentication", ipcauth.UpCommand("--disable-ssh-auth"))
	}

	if enables(sshServerCurrentlyAllowed(stored), change.serverSSHAllowed) {
		return denyPrivileged(ctx, "enabling the NetBird SSH server", ipcauth.UpCommand("--allow-server-ssh"))
	}

	if err := requirePrivilegeForVNCChange(ctx, stored, change); err != nil {
		return err
	}

	// Only guard the management binding while a remote-access server is enabled:
	// that is when the management identity decides who may open a shell or reach
	// the desktop here.
	server, enabled := enabledRemoteAccessServer(stored)
	if !enabled {
		return nil
	}

	if change.managementURL != "" && !sameManagementURL(stored.ManagementURL, change.managementURL) {
		return denyPrivileged(ctx,
			fmt.Sprintf("changing the management URL while the NetBird %s server is enabled", server),
			ipcauth.UpCommand("-m "+change.managementURL))
	}

	return nil
}

// requirePrivilegeForDeregistration refuses to deregister the peer from the
// management server when the caller is not privileged and the profile has a
// remote-access server enabled. Deregistering frees the peer's key to be
// registered against another management identity, which is the same handover the
// management URL check refuses.
//
// Callers that treat deregistration as best-effort (profile removal) continue
// without it; callers that were asked to deregister surface the error.
func requirePrivilegeForDeregistration(ctx context.Context, cfg *profilemanager.Config) error {
	server, enabled := enabledRemoteAccessServer(cfg)
	if !enabled {
		return nil
	}

	return denyPrivileged(ctx,
		fmt.Sprintf("deregistering this peer while the NetBird %s server is enabled", server),
		ipcauth.ElevatedCommand("netbird logout"))
}

// denyPrivileged returns nil when the caller is privileged, and otherwise a
// PermissionDenied whose message names the action and the command that performs
// it with the privileges it needs. The same summary and command ride along as an
// ErrorInfo detail so the CLI and the UI can present them without parsing text.
//
// action reads as the subject of a sentence ("enabling SSH root login"), and
// command is the equivalent command, already elevated for the platform.
func denyPrivileged(ctx context.Context, action, command string) error {
	id, ok := ipcauth.CallerIdentity(ctx)
	if !ok {
		log.Warnf("denying %s: the caller's identity cannot be verified on this control channel", action)
		return privilegeError(unidentifiedSummary(action), reinstallCommand())
	}

	if ipcauth.IsPrivilegedCaller(id) {
		log.Infof("allowing %s for privileged caller %s", action, id)
		return nil
	}

	log.Warnf("denying %s for unprivileged caller %s", action, id)
	actor, command := requiredActor(command)
	return privilegeError(privilegeSummary(action, actor), command)
}

// requiredActor names who may perform the operation and adjusts the command to
// match. A daemon that is not itself privileged delegates to its own identity, so
// telling that host's user to become root is wrong twice over: root is not what the
// daemon checks for, and a rootless container has neither root nor sudo.
func requiredActor(command string) (string, string) {
	self, delegates := ipcauth.SelfDelegatesTo()
	if !delegates {
		return ipcauth.PrivilegedActor(), command
	}
	return fmt.Sprintf("the user the daemon runs as (%s)", self), strings.ReplaceAll(command, "sudo ", "")
}

// privilegeError builds the PermissionDenied carrying summary and command.
func privilegeError(summary, command string) error {
	st := gstatus.New(codes.PermissionDenied, fmt.Sprintf("%s\n\n%s", summary, command))

	detailed, err := st.WithDetails(&errdetails.ErrorInfo{
		Reason: ipcauth.ErrorReasonPrivilegeRequired,
		Domain: ipcauth.ErrorDomain,
		Metadata: map[string]string{
			ipcauth.ErrorMetaSummary: summary,
			ipcauth.ErrorMetaCommand: command,
		},
	})
	if err != nil {
		log.Debugf("attach privilege error detail: %v", err)
		return st.Err()
	}
	return detailed.Err()
}

// privilegeSummary states what is refused and what it needs, in one sentence
// that reads the same in a dialog and in a terminal.
func privilegeSummary(action, actor string) string {
	return fmt.Sprintf("%s requires %s.", capitalize(action), actor)
}

// unidentifiedSummary covers a control channel that carries no caller identity.
// Elevating does not help there, so it points at the daemon's socket instead.
func unidentifiedSummary(action string) string {
	return fmt.Sprintf("%s requires %s, and the daemon cannot verify who is calling over its current socket. "+
		"Reinstall the service on a socket that carries the caller's identity.", capitalize(action), ipcauth.PrivilegedActor())
}

// reinstallCommand is the command that moves the daemon onto a socket whose
// callers can be identified.
func reinstallCommand() string {
	if runtime.GOOS == "windows" {
		return fmt.Sprintf("netbird service install --daemon-addr %s", daemonaddr.WindowsPipeAddr)
	}
	return "sudo netbird service install --daemon-addr unix:///var/run/netbird.sock"
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// enables reports whether requested turns a flag on that is currently off. A
// request that restates the stored value, or turns the flag off, is not a
// privileged change.
func enables(stored, requested *bool) bool {
	if requested == nil || !*requested {
		return false
	}
	return stored == nil || !*stored
}

// storedFlag reads a flag from the stored config, tolerating a config that does
// not exist yet.
func storedFlag(cfg *profilemanager.Config, get func(*profilemanager.Config) *bool) *bool {
	if cfg == nil {
		return nil
	}
	return get(cfg)
}

// sshServerEnabled reports whether the profile currently runs the SSH server.
//
// A nil flag means ON, matching what the engine does with the same config
// (util.ReturnBoolWithDefaultTrue in internal/connect.go, kept for configs written
// before the flag existed). Reading it as OFF here would open the management-URL
// and deregistration guards on exactly those legacy hosts, whose SSH server is
// running. Configs loaded through profilemanager have already been materialised by
// apply(), so this is the same answer by a route that does not depend on that.
func sshServerEnabled(cfg *profilemanager.Config) bool {
	if cfg == nil {
		return false
	}
	return util.ReturnBoolWithDefaultTrue(cfg.ServerSSHAllowed)
}

// sshServerCurrentlyAllowed is the value an enable request is compared against. It
// shares sshServerEnabled's nil-means-on default, so restating "on" for a legacy
// config is correctly seen as no change.
func sshServerCurrentlyAllowed(cfg *profilemanager.Config) *bool {
	enabled := sshServerEnabled(cfg)
	if cfg == nil {
		return nil
	}
	return &enabled
}

// sameManagementURL reports whether requested addresses the same management
// server as stored, comparing scheme, host and effective port so that an
// equivalent spelling ("https://api.netbird.io" for a stored
// "https://api.netbird.io:443") is not treated as a change. It fails closed:
// anything unparseable counts as a change and therefore needs privilege.
func sameManagementURL(stored *url.URL, requested string) bool {
	if stored == nil {
		return false
	}

	// Normalise the requested URL through the config layer's own parser, so the
	// comparison cannot drift from how the value would actually be stored.
	parsed, err := profilemanager.ParseServiceURL("Management URL", requested)
	if err != nil {
		return false
	}

	return stored.Scheme == parsed.Scheme &&
		stored.Hostname() == parsed.Hostname() &&
		effectivePort(stored) == effectivePort(parsed)
}

func effectivePort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	switch u.Scheme {
	case "https":
		return "443"
	case "http":
		return "80"
	default:
		return ""
	}
}
