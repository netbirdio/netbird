package cmd

import (
	"context"
	"runtime"

	"github.com/spf13/cobra"
)

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "installs Netbird service",
	RunE: func(cmd *cobra.Command, args []string) error {
		SetFlagsFromEnvVars()

		cmd.SetOut(cmd.OutOrStdout())

		err := handleRebrand(cmd)
		if err != nil {
			return err
		}

		svcConfig := newSVCConfig()

		svcConfig.Arguments = []string{
			"service",
			"run",
			"--config",
			configPath,
			"--log-level",
			logLevel,
		}

		if managementURL != "" {
			svcConfig.Arguments = append(svcConfig.Arguments, "--management-url")
			svcConfig.Arguments = append(svcConfig.Arguments, managementURL)
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
		cmd.Println("Netbird service has been installed")
		return nil
	},
}

var uninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "uninstalls Netbird service from system",
	RunE: func(cmd *cobra.Command, args []string) error {
		SetFlagsFromEnvVars()

		cmd.SetOut(cmd.OutOrStdout())

		err := handleRebrand(cmd)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithCancel(cmd.Context())

		s, err := newSVC(newProgram(ctx, cancel), newSVCConfig())
		if err != nil {
			return err
		}

		err = s.Uninstall()
		if err != nil {
			return err
		}
		cmd.Println("Netbird has been uninstalled")
		return nil
	},
}
