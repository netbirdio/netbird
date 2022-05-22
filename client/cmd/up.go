package cmd

import (
	"context"
	"fmt"
	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/util"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"
)

var upCmd = &cobra.Command{
	Use:   "up",
	Short: "install, login and start Netbird client",
	RunE: func(cmd *cobra.Command, args []string) error {
		SetFlagsFromEnvVars()

		err := handleRebrand(cmd)
		if err != nil {
			return err
		}

		err = util.InitLog(logLevel, "console")
		if err != nil {
			return fmt.Errorf("failed initializing log %v", err)
		}

		ctx := internal.CtxInitState(cmd.Context())

		// workaround to run without service
		if logFile == "console" {
			config, err := internal.GetConfig(managementURL, adminURL, configPath, preSharedKey)
			if err != nil {
				return fmt.Errorf("get config file: %v", err)
			}

			err = foregroundLogin(ctx, cmd, config, setupKey)
			if err != nil {
				return fmt.Errorf("foreground login failed: %v", err)
			}

			var cancel context.CancelFunc
			ctx, cancel = context.WithCancel(ctx)
			SetupCloseHandler(ctx, cancel)
			return internal.RunClient(ctx, config)
		}

		conn, err := DialClientGRPCServer(ctx, daemonAddr)
		if err != nil {
			return fmt.Errorf("failed to connect to daemon error: %v\n"+
				"If the daemon is not running please run: "+
				"\nnetbird service install \nnetbird service start\n", err)
		}
		defer conn.Close()

		client := proto.NewDaemonServiceClient(conn)

		status, err := client.Status(ctx, &proto.StatusRequest{})
		if err != nil {
			return fmt.Errorf("unable to get daemon status: %v", err)
		}

		if status.Status == string(internal.StatusNeedsLogin) || status.Status == string(internal.StatusLoginFailed) {
			loginRequest := proto.LoginRequest{
				SetupKey:      setupKey,
				PreSharedKey:  preSharedKey,
				ManagementUrl: managementURL,
			}

			var loginErr error

			var loginResp *proto.LoginResponse

			err = WithBackOff(func() error {
				var backOffErr error
				loginResp, backOffErr = client.Login(ctx, &loginRequest)
				if s, ok := gstatus.FromError(backOffErr); ok && (s.Code() == codes.InvalidArgument ||
					s.Code() == codes.PermissionDenied ||
					s.Code() == codes.NotFound ||
					s.Code() == codes.Unimplemented) {
					loginErr = backOffErr
					return nil
				}
				return backOffErr
			})
			if err != nil {
				return fmt.Errorf("login backoff cycle failed: %v", err)
			}

			if loginErr != nil {
				return fmt.Errorf("login failed: %v", loginErr)
			}

			if loginResp.NeedsSSOLogin {
				openURL(cmd, loginResp.VerificationURI, loginResp.VerificationURIComplete, loginResp.UserCode)

				_, err = client.WaitSSOLogin(ctx, &proto.WaitSSOLoginRequest{UserCode: loginResp.UserCode})
				if err != nil {
					return fmt.Errorf("waiting sso login failed with: %v", err)
				}
			}
		} else if status.Status != string(internal.StatusIdle) {
			cmd.Println("Already connected")
			return nil
		}

		if _, err := client.Up(ctx, &proto.UpRequest{}); err != nil {
			return fmt.Errorf("call service up method: %v", err)
		}
		cmd.Println("Connected")
		return nil
	},
}
