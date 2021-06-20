package cmd

import (
	log "github.com/sirupsen/logrus"
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
				log.Fatal(err)
			}

			err = s.Install()
			if err != nil {
				log.Error(err)
			}
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
				log.Fatal(err)
			}

			err = s.Uninstall()
			if err != nil {
				log.Error(err)
			}
		},
	}
)

func init() {
}
