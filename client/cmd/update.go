//go:build windows

package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/client/internal/updatemanager/installer"
	"github.com/netbirdio/netbird/util"
)

var (
	updateCmd = &cobra.Command{
		Use:   "update",
		Short: "Update the NetBird client application",
		RunE:  updateFunc,
	}

	installerPathFlag string
	serviceDirFlag    string
	dryRunFlag        bool
)

func init() {
	updateCmd.Flags().StringVar(&installerPathFlag, "installer-path", "", "path to the installer")
	updateCmd.Flags().StringVar(&serviceDirFlag, "service-dir", "", "service directory")
	updateCmd.Flags().BoolVar(&dryRunFlag, "dry-run", false, "dry run the update process without making any changes")
}

// isUpdateBinary checks if the current executable is named "update" or "update.exe"
func isUpdateBinary() bool {
	execPath, err := os.Executable()
	if err != nil {
		return false
	}

	baseName := filepath.Base(execPath)
	// Remove extension for cross-platform compatibility
	name := strings.TrimSuffix(baseName, filepath.Ext(baseName))

	return name == "update"
}

func updateFunc(cmd *cobra.Command, args []string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("not supported OS: %s", runtime.GOOS)
	}

	// setup log next to the installer path
	if err := setupLogToFile(installerPathFlag); err != nil {
		return err
	}

	log.Infof("updater started: %s", serviceDirFlag)
	updater := installer.NewInstaller()
	if err := updater.Setup(context.Background(), dryRunFlag, installerPathFlag, serviceDirFlag); err != nil {
		log.Errorf("failed to update application: %v", err)
		return err
	}
	return nil
}

func setupLogToFile(installerPath string) error {
	return util.InitLog(logLevel, util.LogConsole, installer.LogFilePath(installerPath))
}
