//go:build windows

package cmd

import (
	"context"

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
)

func init() {
	updateCmd.Flags().StringVar(&installerPathFlag, "installer-path", "", "Path to the installer")
	updateCmd.Flags().StringVar(&serviceDirFlag, "service-dir", "", "Service directory")

}

func updateFunc(cmd *cobra.Command, args []string) error {
	SetFlagsFromEnvVars(rootCmd)
	SetFlagsFromEnvVars(cmd)

	// setup log next to the installer path
	if err := setupLogToFile(installerPathFlag); err != nil {
		return err
	}

	log.Infof("updater started: %s", serviceDirFlag)
	updater := installer.NewInstaller()
	if err := updater.Setup(context.Background(), installerPathFlag, serviceDirFlag); err != nil {
		log.Errorf("failed to update application: %v", err)
		return err
	}
	return nil
}

func setupLogToFile(installerPath string) error {
	return util.InitLog(logLevel, installer.LogFilePath(installerPath))
}
