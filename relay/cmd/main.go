package main

import (
	"os"
	"os/signal"
	"syscall"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/relay/server"
	"github.com/netbirdio/netbird/util"
)

var (
	listenAddress string

	rootCmd = &cobra.Command{
		Use:   "relay",
		Short: "Relay service",
		Long:  "Relay service for Netbird agents",
		Run:   execute,
	}
)

func init() {
	_ = util.InitLog("trace", "console")
	rootCmd.PersistentFlags().StringVarP(&listenAddress, "listen-address", "l", ":1235", "listen address")

}

func waitForExitSignal() {
	osSigs := make(chan os.Signal, 1)
	signal.Notify(osSigs, syscall.SIGINT, syscall.SIGTERM)
	_ = <-osSigs
}

func execute(cmd *cobra.Command, args []string) {
	srv := server.NewServer()
	err := srv.Listen(listenAddress)
	if err != nil {
		log.Errorf("failed to bind server: %s", err)
		os.Exit(1)
	}

	waitForExitSignal()

	err = srv.Close()
	if err != nil {
		log.Errorf("failed to close server: %s", err)
		os.Exit(1)
	}
}

func main() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
