package cmd

import (
	"fmt"
	"github.com/wiretrustee/wiretrustee/client/internal"
	"os"
	"os/signal"
	"runtime"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
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
	managementURL     string

	rootCmd = &cobra.Command{
		Use:   "wiretrustee",
		Short: "",
		Long:  "",
	}

	// Execution control channel for stopCh signal
	stopCh chan int
)

// Execute executes the root command.
func Execute() error {
	return rootCmd.Execute()
}
func init() {

	stopCh = make(chan int)

	defaultConfigPath = "/etc/wiretrustee/config.json"
	if runtime.GOOS == "windows" {
		defaultConfigPath = os.Getenv("PROGRAMDATA") + "\\Wiretrustee\\" + "config.json"
	}

	rootCmd.PersistentFlags().StringVar(&managementURL, "management-url", "", fmt.Sprintf("Management Service URL [http|https]://[host]:[port] (default \"%s\")", internal.ManagementURLDefault().String()))
	rootCmd.PersistentFlags().StringVar(&configPath, "config", defaultConfigPath, "Wiretrustee config file location")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "sets Wiretrustee log level")
	rootCmd.AddCommand(serviceCmd)
	rootCmd.AddCommand(upCmd)
	rootCmd.AddCommand(loginCmd)
	serviceCmd.AddCommand(runCmd, startCmd, stopCmd, restartCmd) // service control commands are subcommands of service
	serviceCmd.AddCommand(installCmd, uninstallCmd)              // service installer commands are subcommands of service
}

// SetupCloseHandler handles SIGTERM signal and exits with success
func SetupCloseHandler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			fmt.Println("\r- Ctrl+C pressed in Terminal")
			stopCh <- 0
		}
	}()
}

// InitLog parses and sets log-level input
func InitLog(logLevel string) {
	level, err := log.ParseLevel(logLevel)
	if err != nil {
		log.Errorf("Failed parsing log-level %s: %s", logLevel, err)
		os.Exit(ExitSetupFailed)
	}
	log.SetLevel(level)
}
