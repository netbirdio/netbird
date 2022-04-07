package cmd

import (
	"context"

	"github.com/netbirdio/netbird/util"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/proto"
)

var upCmd = &cobra.Command{
	Use:   "up",
	Short: "install, login and start wiretrustee client",
	RunE: func(cmd *cobra.Command, args []string) error {
		SetFlagsFromEnvVars()

		err := util.InitLog(logLevel, logFile)
		if err != nil {
			log.Errorf("failed initializing log %v", err)
			return err
		}

		ctx := internal.CtxInitState(cmd.Context())

		// workaround to run without service
		if logFile == "console" {
			config, err := internal.GetConfig(managementURL, configPath, preSharedKey)
			if err != nil {
				log.Errorf("get config file: %v", err)
				return err
			}
			err = WithBackOff(func() error {
				return internal.Login(ctx, config, setupKey)
			})
			if err != nil {
				log.Errorf("backoff cycle failed: %v", err)
				return err
			}

			var cancel context.CancelFunc
			ctx, cancel = context.WithCancel(ctx)
			SetupCloseHandler(ctx, cancel)
			return internal.RunClient(ctx, config)
		}

		conn, err := DialClientGRPCServer(ctx, daemonAddr)
		if err != nil {
			log.Errorf("failed to connect to service CLI interface %v", err)
			return err
		}
		defer conn.Close()

		daemonClient := proto.NewDaemonServiceClient(conn)

		loginRequest := proto.LoginRequest{
			SetupKey:      setupKey,
			PreSharedKey:  preSharedKey,
			ManagementUrl: managementURL,
		}
		err = WithBackOff(func() error {
			_, err := daemonClient.Login(ctx, &loginRequest)
			return err
		})
		if err != nil {
			log.Errorf("backoff cycle failed: %v", err)
			return err
		}

		status, err := daemonClient.Status(ctx, &proto.StatusRequest{})
		if err != nil {
			log.Errorf("get status: %v", err)
			return err
		}

		if status.Status != string(internal.StatusIdle) {
			log.Warnf("already connected")
			return nil
		}

		if _, err := daemonClient.Up(ctx, &proto.UpRequest{}); err != nil {
			log.Errorf("call service up method: %v", err)
			return err
		}

		return nil
	},
}
