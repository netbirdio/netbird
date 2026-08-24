package cmd

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/version"
)

const (
	// ExitSetupFailed defines exit code
	ExitSetupFailed = 1
)

var (
	logLevel string
	logFile  string

	rootCmd = &cobra.Command{
		Use:     "netbird-signal",
		Short:   "",
		Long:    "",
		Version: version.NetbirdVersion(),
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
	defaults := defaultConfig()
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", defaults.LogLevel, "")
	rootCmd.PersistentFlags().StringVar(&logFile, "log-file", defaults.LogFile, "sets Netbird log path. If console is specified the log will be output to stdout")
	rootCmd.AddCommand(runCmd)
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
