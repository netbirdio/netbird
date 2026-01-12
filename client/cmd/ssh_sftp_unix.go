//go:build unix

package cmd

import (
	"errors"
	"io"
	"os"

	"github.com/pkg/sftp"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	sshserver "github.com/netbirdio/netbird/client/ssh/server"
)

var (
	sftpUID        uint32
	sftpGID        uint32
	sftpGroupsInt  []uint
	sftpWorkingDir string
)

var sshSftpCmd = &cobra.Command{
	Use:    "sftp",
	Short:  "SFTP server with privilege dropping (internal use)",
	Hidden: true,
	RunE:   sftpMain,
}

func init() {
	sshSftpCmd.Flags().Uint32Var(&sftpUID, "uid", 0, "Target user ID")
	sshSftpCmd.Flags().Uint32Var(&sftpGID, "gid", 0, "Target group ID")
	sshSftpCmd.Flags().UintSliceVar(&sftpGroupsInt, "groups", nil, "Supplementary group IDs (can be repeated)")
	sshSftpCmd.Flags().StringVar(&sftpWorkingDir, "working-dir", "", "Working directory")
}

func sftpMain(cmd *cobra.Command, _ []string) error {
	privilegeDropper := sshserver.NewPrivilegeDropper(nil)

	var groups []uint32
	for _, groupInt := range sftpGroupsInt {
		groups = append(groups, uint32(groupInt))
	}

	config := sshserver.ExecutorConfig{
		UID:        sftpUID,
		GID:        sftpGID,
		Groups:     groups,
		WorkingDir: sftpWorkingDir,
		Shell:      "",
		Command:    "",
	}

	log.Tracef("dropping privileges for SFTP to UID=%d, GID=%d, groups=%v", config.UID, config.GID, config.Groups)

	if err := privilegeDropper.DropPrivileges(config.UID, config.GID, config.Groups); err != nil {
		cmd.PrintErrf("privilege drop failed: %v\n", err)
		os.Exit(sshserver.ExitCodePrivilegeDropFail)
	}

	if config.WorkingDir != "" {
		if err := os.Chdir(config.WorkingDir); err != nil {
			cmd.PrintErrf("failed to change to working directory %s: %v\n", config.WorkingDir, err)
		}
	}

	sftpServer, err := sftp.NewServer(struct {
		io.Reader
		io.WriteCloser
	}{
		Reader:      os.Stdin,
		WriteCloser: os.Stdout,
	})
	if err != nil {
		cmd.PrintErrf("SFTP server creation failed: %v\n", err)
		os.Exit(sshserver.ExitCodeShellExecFail)
	}

	log.Tracef("starting SFTP server with dropped privileges")
	if err := sftpServer.Serve(); err != nil && !errors.Is(err, io.EOF) {
		cmd.PrintErrf("SFTP server error: %v\n", err)
		if closeErr := sftpServer.Close(); closeErr != nil {
			cmd.PrintErrf("SFTP server close error: %v\n", closeErr)
		}
		os.Exit(sshserver.ExitCodeShellExecFail)
	}

	if closeErr := sftpServer.Close(); closeErr != nil {
		cmd.PrintErrf("SFTP server close error: %v\n", closeErr)
	}
	os.Exit(sshserver.ExitCodeSuccess)
	return nil
}
