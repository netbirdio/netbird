package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/client/internal"
)

func init() {
	installCmd.PersistentFlags().StringVarP(&logLevel, "log-level", "l", "info", "sets Netbird log level")
	installCmd.PersistentFlags().StringVar(&logFile, "log-file", defaultLogFile, "sets Netbird log path. If console is specified the the log will be output to stdout")
	installCmd.PersistentFlags().StringVarP(&configPath, "config", "c", defaultConfigPath, "Netbird config file location")
	installCmd.PersistentFlags().StringVarP(&managementURL, "management-url", "m", "", fmt.Sprintf("Management Service URL [http|https]://[host]:[port] (default \"%s\")", internal.DefaultManagementURL))
}

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "installs Netbird service",
	RunE: func(cmd *cobra.Command, args []string) error {
		SetFlagsFromEnvVars(rootCmd)

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
			svcConfig.Arguments = append(svcConfig.Arguments, "--management-url", managementURL)
		}

		if logFile != "console" {
			svcConfig.Arguments = append(svcConfig.Arguments, "--log-file", logFile)
		}

		if runtime.GOOS == "linux" {
			// Respected only by systemd systems
			svcConfig.Dependencies = []string{"After=network.target syslog.target"}

			if logFile != "console" {
				setStdLogPath := true
				dir := filepath.Dir(logFile)

				_, err := os.Stat(dir)
				if err != nil {
					err = os.MkdirAll(dir, 0750)
					if err != nil {
						setStdLogPath = false
					}
				}

				if setStdLogPath {
					svcConfig.Option["LogOutput"] = true
					svcConfig.Option["LogDirectory"] = dir
				}
			}
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
		SetFlagsFromEnvVars(rootCmd)

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
