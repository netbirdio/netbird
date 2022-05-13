package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"

	"github.com/spf13/cobra"
)

const (
	// ExitSetupFailed defines exit code
	ExitSetupFailed = 1
)

var (
	configPath        string
	defaultConfigPath string
	logLevel          string
	defaultLogFile    string
	logFile           string

	rootCmd = &cobra.Command{
		Use:   "netbird-mgmt",
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

	defaultMgmtDataDir = "/var/lib/netbird/"
	defaultConfigPath = "/etc/netbird"
	defaultMgmtConfig = defaultConfigPath + "/management.json"
	defaultLogFile = "/var/log/netbird/management.log"

	if runtime.GOOS == "windows" {
		defaultConfigPath = os.Getenv("PROGRAMDATA") + "\\Netbird\\" + "management.json"
		defaultLogFile = os.Getenv("PROGRAMDATA") + "\\Netbird\\" + "management.log"
	}

	rootCmd.PersistentFlags().StringVar(&configPath, "config", defaultConfigPath, "Netbird config file location to write new config to")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "")
	rootCmd.PersistentFlags().StringVar(&logFile, "log-file", defaultLogFile, "sets Netbird log path. If console is specified the the log will be output to stdout")
	rootCmd.AddCommand(mgmtCmd)
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
