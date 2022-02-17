package cmd

import (
	"context"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	"github.com/wiretrustee/wiretrustee/client/internal"
	"github.com/wiretrustee/wiretrustee/client/proto"
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "login to the Wiretrustee Management Service (first run)",
	RunE: func(cmd *cobra.Command, args []string) error {
		SetFlagsFromEnvVars()

		// workaround to run without service
		if logFile == "console" {
			config, err := internal.GetConfig(managementURL, configPath, preSharedKey)
			if err != nil {
				log.Errorf("get config file: %v", err)
				return err
			}
			if err = internal.Login(config, setupKey); err != nil {
				log.Errorf("login: %v", err)
				return err
			}
			return nil
		}

		if setupKey == "" {
			log.Error("setup key can't be empty")
			return fmt.Errorf("empty setup key")
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
		defer cancel()

		conn, err := grpc.DialContext(ctx, daemonAddr, grpc.WithInsecure())
		if err != nil {
			log.Errorf("failed to connect to service CLI interface %v", err)
			return err
		}

		request := proto.LoginRequest{
			SetupKey:     setupKey,
			PresharedKey: preSharedKey,
		}
		if _, err := proto.NewDaemonServiceClient(conn).Login(ctx, &request); err != nil {
			log.Error("can't call service login method", err)
			log.Info("please, check service is installed correctly")
		}
		return nil
	},
}

