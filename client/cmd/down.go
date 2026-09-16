package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/netbirdio/netbird/util"

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

		if err := util.InitLog(logLevel, util.LogConsole); err != nil {
			return fmt.Errorf("initialize log: %w", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Second*20)
		defer cancel()

		conn, err := DialClientGRPCServer(ctx, daemonAddr)
		if err != nil {
			return fmt.Errorf("connect to service CLI interface: %w", err)
		}
		defer conn.Close()

		daemonClient := proto.NewDaemonServiceClient(conn)

		if _, err := daemonClient.Down(ctx, &proto.DownRequest{}); err != nil {
			return daemonCallError("call service down method", err)
		}

		cmd.Println("Disconnected")
		return nil
	},
}
