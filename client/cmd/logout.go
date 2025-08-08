package cmd

import (
	"context"
	"fmt"
	"os/user"
	"time"

	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/client/proto"
)

var logoutCmd = &cobra.Command{
	Use:     "deregister",
	Aliases: []string{"logout"},
	Short:   "deregister from the NetBird Management Service and delete peer",
	RunE: func(cmd *cobra.Command, args []string) error {
		SetFlagsFromEnvVars(rootCmd)

		cmd.SetOut(cmd.OutOrStdout())

		ctx, cancel := context.WithTimeout(context.Background(), time.Second*15)
		defer cancel()

		conn, err := DialClientGRPCServer(ctx, daemonAddr)
		if err != nil {
			return fmt.Errorf("connect to daemon: %v", err)
		}
		defer conn.Close()

		daemonClient := proto.NewDaemonServiceClient(conn)

		req := &proto.LogoutRequest{}

		if profileName != "" {
			req.ProfileName = &profileName

			currUser, err := user.Current()
			if err != nil {
				return fmt.Errorf("get current user: %v", err)
			}
			username := currUser.Username
			req.Username = &username
		}

		if _, err := daemonClient.Logout(ctx, req); err != nil {
			return fmt.Errorf("deregister: %v", err)
		}

		cmd.Println("Deregistered successfully")
		return nil
	},
}

func init() {
	logoutCmd.PersistentFlags().StringVar(&profileName, profileNameFlag, "", profileNameDesc)
}
