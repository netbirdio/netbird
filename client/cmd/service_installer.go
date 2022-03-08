package cmd

import (
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

		s, err := newSVC(newProgram(cmd, args), svcConfig)
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

		s, err := newSVC(newProgram(cmd, args), newSVCConfig())
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

