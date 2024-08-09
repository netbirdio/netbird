package cmd

import (
	"fmt"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/spf13/cobra"
)

var (
	profileCmd = &cobra.Command{
		Use:   "profile [newProfile]",
		Short: "switch to profile newProfile or get the current one",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := internal.CtxInitState(cmd.Context())

			conn, err := DialClientGRPCServer(ctx, daemonAddr)
			if err != nil {
				return fmt.Errorf("failed to connect to service CLI interface %v", err)
			}

			defer conn.Close()

			daemonClient := proto.NewDaemonServiceClient(conn)

			if (len(args)) == 1 {
				if _, err := daemonClient.SwitchProfile(ctx, &proto.SwitchProfileRequest{Profile: args[0]}); err != nil {
					return err
				}

				return nil
			}

			resp, err := daemonClient.GetProfile(ctx, &proto.GetProfileRequest{})

			if err != nil {
				return err
			}

			cmd.Println(resp.Profile)

			return nil
		},
	}

	profilesCmd = &cobra.Command{
		Use:   "profiles",
		Short: "list all profiles",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := internal.CtxInitState(cmd.Context())

			conn, err := DialClientGRPCServer(ctx, daemonAddr)
			if err != nil {
				return fmt.Errorf("failed to connect to service CLI interface %v", err)
			}

			defer conn.Close()

			daemonClient := proto.NewDaemonServiceClient(conn)
			resp, err := daemonClient.ListProfiles(ctx, &proto.ListProfilesRequest{})

			if err != nil {
				return err
			}

			for _, profile := range resp.Profiles {
				cmd.Println(profile)
			}

			return nil
		},
	}
)
