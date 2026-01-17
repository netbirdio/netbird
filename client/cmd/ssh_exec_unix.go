//go:build unix

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	sshserver "github.com/netbirdio/netbird/client/ssh/server"
)

var (
	sshExecUID        uint32
	sshExecGID        uint32
	sshExecGroups     []uint
	sshExecWorkingDir string
	sshExecShell      string
	sshExecCommand    string
	sshExecPTY        bool
)

// sshExecCmd represents the hidden ssh exec subcommand for privilege dropping
var sshExecCmd = &cobra.Command{
	Use:    "exec",
	Short:  "Internal SSH execution with privilege dropping (hidden)",
	Hidden: true,
	RunE:   runSSHExec,
}

func init() {
	sshExecCmd.Flags().Uint32Var(&sshExecUID, "uid", 0, "Target user ID")
	sshExecCmd.Flags().Uint32Var(&sshExecGID, "gid", 0, "Target group ID")
	sshExecCmd.Flags().UintSliceVar(&sshExecGroups, "groups", nil, "Supplementary group IDs (can be repeated)")
	sshExecCmd.Flags().StringVar(&sshExecWorkingDir, "working-dir", "", "Working directory")
	sshExecCmd.Flags().StringVar(&sshExecShell, "shell", "/bin/sh", "Shell to execute")
	sshExecCmd.Flags().BoolVar(&sshExecPTY, "pty", false, "Request PTY (will fail as executor doesn't support PTY)")
	sshExecCmd.Flags().StringVar(&sshExecCommand, "cmd", "", "Command to execute")

	if err := sshExecCmd.MarkFlagRequired("uid"); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "failed to mark uid flag as required: %v\n", err)
		os.Exit(1)
	}
	if err := sshExecCmd.MarkFlagRequired("gid"); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "failed to mark gid flag as required: %v\n", err)
		os.Exit(1)
	}

	sshCmd.AddCommand(sshExecCmd)
}

// runSSHExec handles the SSH exec subcommand execution.
func runSSHExec(cmd *cobra.Command, _ []string) error {
	privilegeDropper := sshserver.NewPrivilegeDropper(nil)

	var groups []uint32
	for _, groupInt := range sshExecGroups {
		groups = append(groups, uint32(groupInt))
	}

	config := sshserver.ExecutorConfig{
		UID:        sshExecUID,
		GID:        sshExecGID,
		Groups:     groups,
		WorkingDir: sshExecWorkingDir,
		Shell:      sshExecShell,
		Command:    sshExecCommand,
		PTY:        sshExecPTY,
	}

	privilegeDropper.ExecuteWithPrivilegeDrop(cmd.Context(), config)
	return nil
}
