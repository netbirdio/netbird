package cmd

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/wiretrustee/wiretrustee/client/internal"
	"os"
	"os/signal"
	"runtime"
	"syscall"
)

const (
	// ExitSetupFailed defines exit code
	ExitSetupFailed   = 1
	DefaultConfigPath = ""
)

var (
	configPath        string
	defaultConfigPath string
	logLevel          string
	defaultLogFile    string
	logFile           string
	managementURL     string
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
