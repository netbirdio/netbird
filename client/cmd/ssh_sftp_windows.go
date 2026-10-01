//go:build windows

package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"strings"

	"github.com/pkg/sftp"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	sshserver "github.com/netbirdio/netbird/client/ssh/server"
)

var (
	sftpWorkingDir  string
	windowsUsername string
	windowsDomain   string
)

var sshSftpCmd = &cobra.Command{
	Use:    "sftp",
	Short:  "SFTP server with user switching for Windows (internal use)",
	Hidden: true,
	RunE:   sftpMain,
}

func init() {
	sshSftpCmd.Flags().StringVar(&sftpWorkingDir, "working-dir", "", "Working directory")
	sshSftpCmd.Flags().StringVar(&windowsUsername, "windows-username", "", "Windows username for user switching")
	sshSftpCmd.Flags().StringVar(&windowsDomain, "windows-domain", "", "Windows domain for user switching")
}

func sftpMain(cmd *cobra.Command, _ []string) error {
	return sftpMainDirect(cmd)
}

func sftpMainDirect(cmd *cobra.Command) error {
	currentUser, err := user.Current()
	if err != nil {
		cmd.PrintErrf("failed to get current user: %v\n", err)
		os.Exit(sshserver.ExitCodeValidationFail)
	}

	if windowsUsername != "" {
		expectedUsername := windowsUsername
		if windowsDomain != "" {
			expectedUsername = fmt.Sprintf(`%s\%s`, windowsDomain, windowsUsername)
		}
		if !strings.EqualFold(currentUser.Username, expectedUsername) && !strings.EqualFold(currentUser.Username, windowsUsername) {
			cmd.PrintErrf("user switching failed\n")
			os.Exit(sshserver.ExitCodeValidationFail)
		}
	}

	log.Debugf("SFTP process running as: %s (UID: %s, Name: %s)", currentUser.Username, currentUser.Uid, currentUser.Name)

	if sftpWorkingDir != "" {
		if err := os.Chdir(sftpWorkingDir); err != nil {
			cmd.PrintErrf("failed to change to working directory %s: %v\n", sftpWorkingDir, err)
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

	log.Debugf("starting SFTP server")
	exitCode := sshserver.ExitCodeSuccess
	if err := sftpServer.Serve(); err != nil && !errors.Is(err, io.EOF) {
		cmd.PrintErrf("SFTP server error: %v\n", err)
		exitCode = sshserver.ExitCodeShellExecFail
	}

	if err := sftpServer.Close(); err != nil {
		log.Debugf("SFTP server close error: %v", err)
	}

	os.Exit(exitCode)
	return nil
}
