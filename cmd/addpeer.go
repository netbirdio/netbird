package cmd

import (
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/wiretrustee/wiretrustee/connection"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	key        string
	allowedIPs string

	addPeerCmd = &cobra.Command{
		Use:   "add-peer",
		Short: "add remote peer",
		Run: func(cmd *cobra.Command, args []string) {
			InitLog(logLevel)
			err := addPeer(key, allowedIPs)
			if err != nil {
				log.Errorf("Failed to add peer: %s", err)
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

func addPeer(peerKey string, allowedIPs string) error {
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return status.Errorf(codes.FailedPrecondition, "Config doesn't exist, please run 'wiretrustee init' first")
	}

	config, err := Read(configPath)
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "Error reading config file, message: %s", err)
	}
	config.Peers = append(config.Peers, connection.Peer{
		WgPubKey:     key,
		WgAllowedIps: allowedIPs,
	})

	err = config.Write(configPath)
	if err != nil {
		log.Errorf("failed writing config to %s: %s", config, err.Error())
		return status.Errorf(codes.Internal, "failed writing config to %s: %s", configPath, err)
	}

	return nil
}
