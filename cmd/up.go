package cmd

import (
	"context"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/wiretrustee/wiretrustee/connection"
	sig "github.com/wiretrustee/wiretrustee/signal"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"os"
)

var (
	upCmd = &cobra.Command{
		Use:   "up",
		Short: "start wiretrustee",
		Run: func(cmd *cobra.Command, args []string) {
			InitLog(logLevel)

			config, _ := Read(configPath)

			myKey, err := wgtypes.ParseKey(config.PrivateKey)
			if err != nil {
				log.Errorf("failed parsing Wireguard key %s: [%s]", config.PrivateKey, err.Error())
				os.Exit(ExitSetupFailed)
			}

			ctx := context.Background()
			signalClient, err := sig.NewClient(config.SignalAddr, myKey, ctx)
			if err != nil {
				log.Errorf("error while connecting to the Signal Exchange Service %s: %s", config.SignalAddr, err)
				os.Exit(ExitSetupFailed)
			}
			//todo proper close handling
			defer func() { signalClient.Close() }()

			engine := connection.NewEngine(signalClient, config.StunTurnURLs, config.WgIface, config.WgAddr)

			err = engine.Start(myKey, config.Peers)

			//signalClient.WaitConnected()

			SetupCloseHandler()
		},
	}
)

func init() {
}
