package cmd

import (
	"context"
	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/util"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"
)

var upCmd = &cobra.Command{
	Use:   "up",
	Short: "install, login and start wiretrustee client",
	RunE: func(cmd *cobra.Command, args []string) error {
		SetFlagsFromEnvVars()

		err := util.InitLog(logLevel, "console")
		if err != nil {
			log.Errorf("failed initializing log %v", err)
			return err
		}

		ctx := internal.CtxInitState(cmd.Context())

		// workaround to run without service
		if logFile == "console" {
			config, err := internal.GetConfig(managementURL, adminURL, configPath, preSharedKey)
			if err != nil {
				log.Errorf("get config file: %v", err)
				return err
			}

			err = foregroundLogin(ctx, config, setupKey)
			if err != nil {
				log.Errorf("foreground login failed: %v", err)
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

		status, err := daemonClient.Status(ctx, &proto.StatusRequest{})
		if err != nil {
			log.Errorf("unable to get daemon status: %v", err)
			return err
		}

		var loginRequest proto.LoginRequest
		if status.Status == string(internal.StatusNeedsLogin) {
			jwtToken := ""

			if setupKey == "" {
				tokenInfo, err := daemonGetTokenInfo(ctx, daemonClient)
				if err != nil {
					log.Errorf("interactive sso login failed: %v", err)
					return err
				}
				jwtToken = tokenInfo.AccessToken
			}
			loginRequest = proto.LoginRequest{
				SetupKey:      setupKey,
				PreSharedKey:  preSharedKey,
				ManagementUrl: managementURL,
				JwtToken:      jwtToken,
			}

			var loginErr error

			err = WithBackOff(func() error {
				_, err := daemonClient.Login(ctx, &loginRequest)
				if s, ok := gstatus.FromError(err); ok && (s.Code() == codes.InvalidArgument || s.Code() == codes.PermissionDenied) {
					loginErr = err
					return nil
				}
				return err
			})
			if err != nil && loginErr != nil {
				log.Errorf("login backoff cycle failed: %v", err)
				return err
			}

		} else if status.Status != string(internal.StatusIdle) {
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
