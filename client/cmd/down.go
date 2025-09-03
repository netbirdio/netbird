package cmd

import (
	"context"
	"time"

	"github.com/netbirdio/netbird/util"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/client/proto"
)

var downCmd = &cobra.Command{
	Use:   "down",
	Short: "Disconnect from the NetBird network",
	Long:  "Disconnect the NetBird client from the network and management service. This will terminate all active connections with the remote peers.",
	RunE: func(cmd *cobra.Command, args []string) error {
		SetFlagsFromEnvVars(rootCmd)

		cmd.SetOut(cmd.OutOrStdout())

		err := util.InitLog(logLevel, util.LogConsole)
		if err != nil {
			log.Errorf("failed initializing log %v", err)
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Second*7)
		defer cancel()

		conn, err := DialClientGRPCServer(ctx, daemonAddr)
		if err != nil {
			log.Errorf("failed to connect to service CLI interface %v", err)
			return err
		}
		defer conn.Close()

		daemonClient := proto.NewDaemonServiceClient(conn)

		if _, err := daemonClient.Down(ctx, &proto.DownRequest{}); err != nil {
			log.Errorf("call service down method: %v", err)
			return err
		}

		cmd.Println("Disconnected")
		return nil
	},
}
