package cmd

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/util"
)

var dnsCmd = &cobra.Command{
	Use:   "dns",
	Short: "Manage DNS settings",
	Long:  "Commands for managing DNS settings in the NetBird client.",
}

var dnsFlushCacheCmd = &cobra.Command{
	Use:     "flush-cache",
	Short:   "Flush the DNS cache",
	Long:    "Flush the NetBird DNS forwarder cache. Forces the daemon to re-resolve domain names on next lookup.",
	Example: "  netbird dns flush-cache",
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		SetFlagsFromEnvVars(rootCmd)

		cmd.SetOut(cmd.OutOrStdout())

		if err := util.InitLog(logLevel, util.LogConsole); err != nil {
			log.Errorf("failed initializing log %v", err)
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
		defer cancel()

		conn, err := DialClientGRPCServer(ctx, daemonAddr)
		if err != nil {
			log.Errorf("failed to connect to service CLI interface %v", err)
			return err
		}
		defer conn.Close()

		daemonClient := proto.NewDaemonServiceClient(conn)

		if _, err := daemonClient.FlushDNSCache(ctx, &proto.FlushDNSCacheRequest{}); err != nil {
			log.Errorf("call service FlushDNSCache method: %v", err)
			return err
		}

		cmd.Println("DNS cache flushed successfully")
		return nil
	},
}
