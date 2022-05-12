package cmd

import (
	"context"
	"fmt"
	"github.com/netbirdio/netbird/util"

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
			return fmt.Errorf("failed initializing log %v", err)
		}

		ctx := internal.CtxInitState(context.Background())

		conn, err := DialClientGRPCServer(ctx, daemonAddr)
		if err != nil {
			return fmt.Errorf("failed to connect to daemon error: %v\n"+
				"If the daemon is not running please run: "+
				"\nnetbird service install \nnetbird service start\n", err)
		}
		defer conn.Close()

		resp, err := proto.NewDaemonServiceClient(conn).Status(cmd.Context(), &proto.StatusRequest{})
		if err != nil {
			return fmt.Errorf("status failed: %v", status.Convert(err).Message())
		}

		if resp.GetStatus() == string(internal.StatusNeedsLogin) || resp.GetStatus() == string(internal.StatusLoginFailed) {
			// todo: update login doc url
			cmd.Printf("run the command \"netbird up\" to login. If no SSO provider has been set " +
				"in your management server" +
				"you can use a setup-key, " +
				"see more at https://www.netbird.io/docs/overview/setup-keys for more info")
		}

		return nil
	},
}
