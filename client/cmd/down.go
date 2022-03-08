package cmd

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/wiretrustee/wiretrustee/client/proto"
)

var downCmd = &cobra.Command{
	Use:   "down",
	Short: "down wiretrustee connections",
	RunE: func(cmd *cobra.Command, args []string) error {
		SetFlagsFromEnvVars()

		ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
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
		return nil
	},
}
