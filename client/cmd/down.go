package cmd

import (
	"context"
	"time"

	"github.com/netbirdio/netbird/util"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/client/proto"
	nbstatus "github.com/netbirdio/netbird/client/status"
)

var downCmd = &cobra.Command{
	Use:   "down",
	Short: "Disconnect from the NetBird network",
	Long:  "Disconnect the NetBird client from the network and management service. This will terminate all active connections with the remote peers.",
	RunE: func(cmd *cobra.Command, args []string) error {
		SetFlagsFromEnvVars(rootCmd)

		cmd.SetOut(cmd.OutOrStdout())

		err := util.InitLog(logLevel, util.LogConsole)
		if err != nil {
			log.Errorf("failed initializing log %v", err)
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Second*20)
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

		out := &nbstatus.DownOutput{Status: "Disconnected"}
		switch {
		case jsonFlag:
			s, err := out.JSON()
			if err != nil {
				return err
			}
			cmd.Println(s)
		case yamlFlag:
			s, err := out.YAML()
			if err != nil {
				return err
			}
			cmd.Print(s)
		default:
			cmd.Println(out.Status)
		}
		return nil
	},
}

func init() {
	downCmd.PersistentFlags().BoolVarP(&jsonFlag, "json", "j", false, "display command result in json format")
	downCmd.PersistentFlags().BoolVarP(&yamlFlag, "yaml", "y", false, "display command result in yaml format")
	downCmd.MarkFlagsMutuallyExclusive("json", "yaml")
}
