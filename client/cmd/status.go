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
	Short: "status of the Netbird Service",
	RunE: func(cmd *cobra.Command, args []string) error {
		SetFlagsFromEnvVars()

		err := handleRebrand(cmd)
		if err != nil {
			return err
		}

		err = util.InitLog(logLevel, "console")
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

		cmd.Printf("Status: %s\n\n", resp.GetStatus())
		if resp.GetStatus() == string(internal.StatusNeedsLogin) || resp.GetStatus() == string(internal.StatusLoginFailed) {

			cmd.Printf("Run UP command to log in with SSO (interactive login):\n\n" +
				" netbird up \n\n" +
				"If you are running a self-hosted version and no SSO provider has been configured in your Management Server,\n" +
				"you can use a setup-key:\n\n netbird up --management-url <YOUR_MANAGEMENT_URL> --setup-key <YOUR_SETUP_KEY>\n\n" +
				"More info: https://www.netbird.io/docs/overview/setup-keys\n\n")
		}

		return nil
	},
}
