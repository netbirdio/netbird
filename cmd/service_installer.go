package cmd

import (
	"github.com/spf13/cobra"
	"runtime"
)

var (
	installCmd = &cobra.Command{
		Use:   "install",
		Short: "installs wiretrustee service",
		Run: func(cmd *cobra.Command, args []string) {

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

			s, err := newSVC(&program{}, svcConfig)
			if err != nil {
				cmd.PrintErrln(err)
				return
			}

			err = s.Install()
			if err != nil {
				cmd.PrintErrln(err)
				return
			}
			cmd.Printf("Wiretrustee service has been installed")
		},
	}
)

var (
	uninstallCmd = &cobra.Command{
		Use:   "uninstall",
		Short: "uninstalls wiretrustee service from system",
		Run: func(cmd *cobra.Command, args []string) {

			s, err := newSVC(&program{}, newSVCConfig())
			if err != nil {
				cmd.PrintErrln(err)
				return
			}

			err = s.Uninstall()
			if err != nil {
				cmd.PrintErrln(err)
				return
			}
			cmd.Printf("Wiretrustee has been uninstalled")
		},
	}
)

func init() {
}
