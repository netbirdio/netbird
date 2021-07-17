package cmd

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/wiretrustee/wiretrustee/connection"
	"os"
)

var (
	key        string
	allowedIPs string

	addPeerCmd = &cobra.Command{
		Use:   "add-peer",
		Short: "add remote peer",
		Run: func(cmd *cobra.Command, args []string) {
			InitLog(logLevel)

			if _, err := os.Stat(configPath); os.IsNotExist(err) {
				log.Error("config doesn't exist, please run 'wiretrustee init' first")
				os.Exit(ExitSetupFailed)
			}

			config, err := Read(configPath)
			if err != nil {
				log.Fatalf("Error reading config file, message: %v", err)
			}
			config.Peers = append(config.Peers, connection.Peer{
				WgPubKey:     key,
				WgAllowedIps: allowedIPs,
			})

			err = config.Write(configPath)
			if err != nil {
				log.Errorf("failed writing config to %s: %s", config, err.Error())
				os.Exit(ExitSetupFailed)
			}
		},
	}
)

func init() {
	addPeerCmd.PersistentFlags().StringVar(&key, "key", "", "Wireguard public key of the remote peer")
	addPeerCmd.PersistentFlags().StringVar(&allowedIPs, "allowedIPs", "", "Wireguard Allowed IPs for the remote peer, e.g 10.30.30.2/32")
	addPeerCmd.MarkPersistentFlagRequired("key")        //nolint
	addPeerCmd.MarkPersistentFlagRequired("allowedIPs") //nolint
}
