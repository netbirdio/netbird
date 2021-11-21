package cmd

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/wiretrustee/wiretrustee/client/internal"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
)

var (
	configPath        string
	defaultConfigPath string
	logLevel          string
	defaultLogFile    string
	logFile           string
	managementURL     string
	setupKey          string
	preSharedKey      string
	rootCmd           = &cobra.Command{
		Use:   "wiretrustee",
		Short: "",
		Long:  "",
	}

	// Execution control channel for stopCh signal
	stopCh    chan int
	cleanupCh chan struct{}
)

// Execute executes the root command.
func Execute() error {
	return rootCmd.Execute()
}
func init() {

	stopCh = make(chan int)
	cleanupCh = make(chan struct{})

	defaultConfigPath = "/etc/wiretrustee/config.json"
	defaultLogFile = "/var/log/wiretrustee/client.log"
	if runtime.GOOS == "windows" {
		defaultConfigPath = os.Getenv("PROGRAMDATA") + "\\Wiretrustee\\" + "config.json"
		defaultLogFile = os.Getenv("PROGRAMDATA") + "\\Wiretrustee\\" + "client.log"
	}

	rootCmd.PersistentFlags().StringVar(&managementURL, "management-url", "", fmt.Sprintf("Management Service URL [http|https]://[host]:[port] (default \"%s\")", internal.ManagementURLDefault().String()))
	rootCmd.PersistentFlags().StringVar(&configPath, "config", defaultConfigPath, "Wiretrustee config file location")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "sets Wiretrustee log level")
	rootCmd.PersistentFlags().StringVar(&logFile, "log-file", defaultLogFile, "sets Wiretrustee log path. If console is specified the the log will be output to stdout")
	rootCmd.PersistentFlags().StringVar(&setupKey, "setup-key", "", "Setup key obtained from the Management Service Dashboard (used to register peer)")
	rootCmd.PersistentFlags().StringVar(&preSharedKey, "preshared-key", "", "Sets Wireguard PreSharedKey property. If set, then only peers that have the same key can communicate.")
	rootCmd.AddCommand(serviceCmd)
	rootCmd.AddCommand(upCmd)
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(versionCmd)
	serviceCmd.AddCommand(runCmd, startCmd, stopCmd, restartCmd) // service control commands are subcommands of service
	serviceCmd.AddCommand(installCmd, uninstallCmd)              // service installer commands are subcommands of service
}

// SetupCloseHandler handles SIGTERM signal and exits with success
func SetupCloseHandler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for range c {
			log.Info("shutdown signal received")
			stopCh <- 0
		}
	}()
}

// SetFlagsFromEnvVars reads and updates flag values from environment variables with prefix WT_
func SetFlagsFromEnvVars() {
	flags := rootCmd.PersistentFlags()
	flags.VisitAll(func(f *pflag.Flag) {

		envVar := FlagNameToEnvVar(f.Name)

		if value, present := os.LookupEnv(envVar); present {
			err := flags.Set(f.Name, value)
			if err != nil {
				log.Infof("unable to configure flag %s using variable %s, err: %v", f.Name, envVar, err)
			}
		}
	})
}

// FlagNameToEnvVar converts flag name to environment var name adding a prefix,
// replacing dashes and making all uppercase (e.g. setup-keys is converted to WT_SETUP_KEYS)
func FlagNameToEnvVar(f string) string {
	prefix := "WT_"
	parsed := strings.ReplaceAll(f, "-", "_")
	upper := strings.ToUpper(parsed)
	return prefix + upper
}
