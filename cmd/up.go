package cmd

import (
	"context"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/wiretrustee/wiretrustee/connection"
	sig "github.com/wiretrustee/wiretrustee/signal"
	"os"
)

var (
	upCmd = &cobra.Command{
		Use:   "up",
		Short: "start wiretrustee",
		Run: func(cmd *cobra.Command, args []string) {
			InitLog(logLevel)

			config, _ := Read(configPath)

			ctx := context.Background()
			signalClient, err := sig.NewClient(config.SignalAddr, ctx)
			if err != nil {
				log.Errorf("error while connecting to the Signal Exchange Service %s: %s", config.SignalAddr, err)
				os.Exit(ExitSetupFailed)
			}
			//todo proper close handling
			defer func() { signalClient.Close() }()

			engine := connection.NewEngine(signalClient, config.StunTurnURLs, config.WgIface, config.WgAddr)

			err = engine.Start(config.PrivateKey, config.Peers)

			//signalClient.WaitConnected()

			SetupCloseHandler()
		},
	}
)

func init() {
}
