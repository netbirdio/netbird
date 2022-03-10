package cmd

import (
	"context"
	"github.com/wiretrustee/wiretrustee/util"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"

	"github.com/wiretrustee/wiretrustee/client/internal"
	"github.com/wiretrustee/wiretrustee/client/proto"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "status of the Wiretrustee Service",
	RunE: func(cmd *cobra.Command, args []string) error {
		SetFlagsFromEnvVars()

		err := util.InitLog(logLevel, logFile)
		if err != nil {
			log.Errorf("failed initializing log %v", err)
			return err
		}

		ctx := internal.CtxInitState(context.Background())

		conn, err := DialClientGRPCServer(ctx, daemonAddr)
		if err != nil {
			log.Errorf("failed to connect to service CLI interface %v", err)
			return err
		}
		defer conn.Close()

		resp, err := proto.NewDaemonServiceClient(conn).Status(cmd.Context(), &proto.StatusRequest{})
		if err != nil {
			log.Errorf("status failed: %v", status.Convert(err).Message())
			return nil
		}

		log.Infof("status: %v", resp.Status)
		return nil
	},
}
