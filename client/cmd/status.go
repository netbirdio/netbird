package cmd

import (
	"context"
	"github.com/netbirdio/netbird/util"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/proto"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "status of the Wiretrustee Service",
	RunE: func(cmd *cobra.Command, args []string) error {
		SetFlagsFromEnvVars()

		err := util.InitLog(logLevel, "console")
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

		if resp.GetStatus() == string(internal.StatusNeedsLogin) {
			// todo: update login doc url
			log.Info("run the \"netbird up\" to login if no SSO provider has been set you can use a setup-key, " +
				"see more at https://www.netbird.io/docs/overview/setup-keys for more info")
		}

		return nil
	},
}
