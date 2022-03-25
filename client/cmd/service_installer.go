package cmd

import (
	"context"
	"runtime"

	"github.com/spf13/cobra"
)

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "installs wiretrustee service",
	RunE: func(cmd *cobra.Command, args []string) error {
		SetFlagsFromEnvVars()

		svcConfig := newSVCConfig()

		svcConfig.Arguments = []string{
			"service",
			"run",
			"--config",
			configPath,
			"--log-level",
			logLevel,
		}

		if runtime.GOOS == "linux" {
			// Respected only by systemd systems
			svcConfig.Dependencies = []string{"After=network.target syslog.target"}
		}

		ctx, cancel := context.WithCancel(cmd.Context())

		s, err := newSVC(newProgram(ctx, cancel), svcConfig)
		if err != nil {
			cmd.PrintErrln(err)
			return err
		}

		err = s.Install()
		if err != nil {
			cmd.PrintErrln(err)
			return err
		}
		cmd.Println("Wiretrustee service has been installed")
		return nil
	},
}

var uninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "uninstalls wiretrustee service from system",
	Run: func(cmd *cobra.Command, args []string) {
		SetFlagsFromEnvVars()

		ctx, cancel := context.WithCancel(cmd.Context())

		s, err := newSVC(newProgram(ctx, cancel), newSVCConfig())
		if err != nil {
			cmd.PrintErrln(err)
			return
		}

		err = s.Uninstall()
		if err != nil {
			cmd.PrintErrln(err)
			return
		}
		cmd.Println("Wiretrustee has been uninstalled")
	},
}
