package cmd

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/wiretrustee/wiretrustee/client/internal"
	"github.com/wiretrustee/wiretrustee/client/proto"
)

var upCmd = &cobra.Command{
	Use:   "up",
	Short: "install, login and start wiretrustee client",
	RunE: func(cmd *cobra.Command, args []string) error {
		SetFlagsFromEnvVars()
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

			SetupCloseHandler()
			return internal.RunClient(ctx, config, stopCh, cleanupCh)
		}

		conn, err := DialClientGRPCServer(ctx, daemonAddr)
		if err != nil {
			log.Errorf("failed to connect to service CLI interface %v", err)
			return err
		}
		defer conn.Close()

		daemonClient := proto.NewDaemonServiceClient(conn)

		loginRequest := proto.LoginRequest{
			SetupKey:     setupKey,
			PresharedKey: preSharedKey,
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
