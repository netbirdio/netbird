package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/client/proto"
)

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "logout from the Netbird Management Service and delete peer",
	RunE: func(cmd *cobra.Command, args []string) error {
		SetFlagsFromEnvVars(rootCmd)

		cmd.SetOut(cmd.OutOrStdout())

		ctx, cancel := context.WithTimeout(context.Background(), time.Second*7)
		defer cancel()

		conn, err := DialClientGRPCServer(ctx, daemonAddr)
		if err != nil {
			return fmt.Errorf("connect to daemon: %v", err)
		}
		defer conn.Close()

		daemonClient := proto.NewDaemonServiceClient(conn)

		if _, err := daemonClient.Logout(ctx, &proto.LogoutRequest{}); err != nil {
			return fmt.Errorf("logout: %v", err)
		}

		cmd.Println("Logged out successfully")
		return nil
	},
}
