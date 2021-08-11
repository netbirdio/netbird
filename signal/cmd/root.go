package cmd

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"os"
	"os/signal"
)

const (
	// ExitSetupFailed defines exit code
	ExitSetupFailed = 1
)

var (
	logLevel string

	rootCmd = &cobra.Command{
		Use:   "wiretrustee-signal",
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

	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "")
	rootCmd.AddCommand(signalCmd)
	InitLog(logLevel)
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
