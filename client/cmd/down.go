package cmd

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	"github.com/wiretrustee/wiretrustee/client/proto"
)

var downCmd = &cobra.Command{
	Use:   "down",
	Short: "stop wiretrustee client",
	RunE: func(cmd *cobra.Command, args []string) error {
		SetFlagsFromEnvVars()

		ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
		defer cancel()

		conn, err := grpc.DialContext(ctx, daemonAddr, grpc.WithInsecure())
		if err != nil {
			log.Errorf("failed to connect to service CLI interface %v", err)
			return err
		}

		daemonClient := proto.NewDaemonServiceClient(conn)

		if _, err := daemonClient.Down(ctx, &proto.DownRequest{}); err != nil {
			log.Errorf("call service up method: %v", err)
			return err
		}
		return nil
	},
}
