//go:build windows || darwin

package cmd

import (
	"context"
	"os"
	"path/filepath"
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

	tempDirFlag    string
	installerFile  string
	serviceDirFlag string
	dryRunFlag     bool
)

func init() {
	updateCmd.Flags().StringVar(&tempDirFlag, "temp-dir", "", "temporary dir")
	updateCmd.Flags().StringVar(&installerFile, "installer-file", "", "installer file")
	updateCmd.Flags().StringVar(&serviceDirFlag, "service-dir", "", "service directory")
	updateCmd.Flags().BoolVar(&dryRunFlag, "dry-run", false, "dry run the update process without making any changes")
}

// isUpdateBinary checks if the current executable is named "update" or "update.exe"
func isUpdateBinary() bool {
	// Remove extension for cross-platform compatibility
	execPath, err := os.Executable()
	if err != nil {
		return false
	}
	baseName := filepath.Base(execPath)
	name := strings.TrimSuffix(baseName, filepath.Ext(baseName))

	return name == installer.UpdaterBinaryNameWithoutExtension()
}

func updateFunc(cmd *cobra.Command, args []string) error {
	if err := setupLogToFile(tempDirFlag); err != nil {
		return err
	}

	log.Infof("updater started: %s", serviceDirFlag)
	updater := installer.NewWithDir(tempDirFlag)
	if err := updater.Setup(context.Background(), dryRunFlag, installerFile, serviceDirFlag); err != nil {
		log.Errorf("failed to update application: %v", err)
		return err
	}
	return nil
}

func setupLogToFile(dir string) error {
	logFile := filepath.Join(dir, installer.LogFile)

	if _, err := os.Stat(logFile); err == nil {
		if err := os.Remove(logFile); err != nil {
			log.Errorf("failed to remove existing log file: %v\n", err)
		}
	}

	return util.InitLog(logLevel, util.LogConsole, logFile)
}
