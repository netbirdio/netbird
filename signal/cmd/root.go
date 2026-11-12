package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/version"
)

const (
	// ExitSetupFailed defines exit code
	ExitSetupFailed = 1
)

var (
	logLevel       string
	defaultLogFile string
	logFile        string

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
	// Buffered so a server failure before the run loop waits is not dropped.
	stopCh = make(chan int, 1)
	defaultLogFile = "/var/log/netbird/signal.log"

	if runtime.GOOS == "windows" {
		defaultLogFile = os.Getenv("PROGRAMDATA") + "\\Netbird\\" + "signal.log"
	}

	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "")
	rootCmd.PersistentFlags().StringVar(&logFile, "log-file", defaultLogFile, "sets Netbird log path. If console is specified the log will be output to stdout")
	rootCmd.AddCommand(runCmd)
}

// SetupCloseHandler handles SIGINT and SIGTERM and exits with success. Docker
// and Kubernetes stop the container with SIGTERM.
func SetupCloseHandler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		for sig := range c {
			fmt.Printf("\r- received %s\n", sig)
			stopCh <- 0
		}
	}()
}
