package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// SetSSHConfigCmdName is the hidden subcommand an elevated process runs to apply
// the privileged SSH settings.
const SetSSHConfigCmdName = "set-ssh-config"

// sshConfigElevated is set by runInDaemonMode once the dangerous SSH settings
// have been applied by an elevated helper, so the (unprivileged) up flow does
// not re-send them and re-trip the daemon gate.
var sshConfigElevated bool

// wantsDangerousSSH reports whether this invocation is trying to ENABLE SSH root
// login or DISABLE SSH authentication.
func wantsDangerousSSH(cmd *cobra.Command) bool {
	return (cmd.Flags().Changed(enableSSHRootFlag) && enableSSHRoot) ||
		(cmd.Flags().Changed(disableSSHAuthFlag) && disableSSHAuth)
}

// buildSetSSHConfigArgs builds the argument list for an elevated
// `netbird set-ssh-config` invocation.
func buildSetSSHConfigArgs(profileName, username string, enableSSHRoot, disableSSHAuth *bool, daemonAddr string) []string {
	args := []string{SetSSHConfigCmdName}
	if profileName != "" {
		args = append(args, "--profile", profileName)
	}
	if username != "" {
		args = append(args, "--username", username)
	}
	if enableSSHRoot != nil && *enableSSHRoot {
		args = append(args, "--"+enableSSHRootFlag)
	}
	if disableSSHAuth != nil && *disableSSHAuth {
		args = append(args, "--"+disableSSHAuthFlag)
	}
	if daemonAddr != "" {
		args = append(args, "--daemon-addr", daemonAddr)
	}
	return args
}

// ElevateSSHConfig re-runs the current executable's `set-ssh-config` command with
// root/administrator privileges via the platform's prompt (pkexec/UAC/osascript),
// so the elevated process connects to the daemon with a privileged identity and
// the daemon's requirePrivilegedForDangerousSSH gate passes.
func ElevateSSHConfig(profileName, username string, enableSSHRoot, disableSSHAuth *bool) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate executable for elevation: %w", err)
	}
	return runElevated(exe, buildSetSSHConfigArgs(profileName, username, enableSSHRoot, disableSSHAuth, daemonAddr))
}
