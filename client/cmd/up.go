package cmd

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	"github.com/wiretrustee/wiretrustee/client/internal"
	"github.com/wiretrustee/wiretrustee/client/proto"
)

var upCmd = &cobra.Command{
	Use:   "up",
	Short: "install, login and start wiretrustee client",
	RunE: func(cmd *cobra.Command, args []string) error {
		SetFlagsFromEnvVars()

		// workaround to run without service
		if logFile == "console" {
			config, err := internal.GetConfig(managementURL, configPath, preSharedKey)
			if err != nil {
				log.Errorf("get config file: %v", err)
				return err
			}
			if err := internal.Login(config, setupKey); err != nil {
				log.Errorf("login: %v", err)
				return err
			}

			SetupCloseHandler()
			return internal.RunClient(config, stopCh, cleanupCh)
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
		defer cancel()

		conn, err := grpc.DialContext(ctx, daemonAddr, grpc.WithInsecure())
		if err != nil {
			log.Errorf("failed to connect to service CLI interface %v", err)
			return err
		}

		daemonClient := proto.NewDaemonServiceClient(conn)

		loginRequest := proto.LoginRequest{
			SetupKey:     setupKey,
			PresharedKey: preSharedKey,
		}
		if _, err := daemonClient.Login(ctx, &loginRequest); err != nil {
			log.Errorf("call service login method: %v", err)
			return err
		}

		if _, err := daemonClient.Up(ctx, &proto.UpRequest{}); err != nil {
			log.Errorf("call service up method: %v", err)
			return err
		}

		return nil
	},
}
