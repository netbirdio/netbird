package cmd

import (
	"context"
	"fmt"

	"github.com/netbirdio/netbird/util"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/proto"
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "login to the Wiretrustee Management Service (first run)",
	RunE: func(cmd *cobra.Command, args []string) error {
		SetFlagsFromEnvVars()

		err := util.InitLog(logLevel, logFile)
		if err != nil {
			log.Errorf("failed initializing log %v", err)
			return err
		}

		ctx := internal.CtxInitState(context.Background())

		// workaround to run without service
		if logFile == "console" {
			config, err := internal.GetConfig(managementURL, adminURL, configPath, preSharedKey)
			if err != nil {
				log.Errorf("get config file: %v", err)
				return err
			}
			err = WithBackOff(func() error {
				return internal.Login(ctx, config, setupKey)
			})
			if err != nil {
				log.Errorf("backoff cycle failed: %v", err)
			}
			return err
		}

		if setupKey == "" {
			log.Error("setup key can't be empty")
			return fmt.Errorf("empty setup key")
		}

		conn, err := DialClientGRPCServer(ctx, daemonAddr)
		if err != nil {
			log.Errorf("failed to connect to service CLI interface %v", err)
			return err
		}
		defer conn.Close()

		request := proto.LoginRequest{
			SetupKey:      setupKey,
			PreSharedKey:  preSharedKey,
			ManagementUrl: managementURL,
		}
		client := proto.NewDaemonServiceClient(conn)
		err = WithBackOff(func() error {
			if _, err := client.Login(ctx, &request); err != nil {
				log.Errorf("try login: %v", err)
			}
			return err
		})
		if err != nil {
			log.Errorf("backoff cycle failed: %v", err)
		}
		return err
	},
}
