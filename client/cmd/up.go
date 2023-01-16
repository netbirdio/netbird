package cmd

import (
	"context"
	"fmt"
	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/proto"
	nbStatus "github.com/netbirdio/netbird/client/status"
	"github.com/netbirdio/netbird/util"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"
)

var (
	foregroundMode bool
	upCmd          = &cobra.Command{
		Use:   "up",
		Short: "install, login and start Netbird client",
		RunE:  upFunc,
	}
)

func init() {
	upCmd.PersistentFlags().BoolVarP(&foregroundMode, "foreground-mode", "F", false, "start service in foreground")
}

func upFunc(cmd *cobra.Command, args []string) error {
	SetFlagsFromEnvVars()

	cmd.SetOut(cmd.OutOrStdout())

	err := util.InitLog(logLevel, "console")
	if err != nil {
		return fmt.Errorf("failed initializing log %v", err)
	}

	ctx := internal.CtxInitState(cmd.Context())

	if foregroundMode {
		return runInForegroundMode(ctx, cmd)
	}
	return runInDaemonMode(ctx, cmd)
}

func runInForegroundMode(ctx context.Context, cmd *cobra.Command) error {
	err := handleRebrand(cmd)
	if err != nil {
		return err
	}

	config, err := internal.GetConfig(internal.ConfigInput{
		ManagementURL: managementURL,
		AdminURL:      adminURL,
		ConfigPath:    configPath,
		PreSharedKey:  &preSharedKey,
	})
	if err != nil {
		return fmt.Errorf("get config file: %v", err)
	}

	config, _ = internal.UpdateOldManagementPort(ctx, config, configPath)

	err = foregroundLogin(ctx, cmd, config, setupKey)
	if err != nil {
		return fmt.Errorf("foreground login failed: %v", err)
	}

	var cancel context.CancelFunc
	ctx, cancel = context.WithCancel(ctx)
	SetupCloseHandler(ctx, cancel)
	return internal.RunClient(ctx, config, nbStatus.NewRecorder())
}

func runInDaemonMode(ctx context.Context, cmd *cobra.Command) error {

	conn, err := DialClientGRPCServer(ctx, daemonAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to daemon error: %v\n"+
			"If the daemon is not running please run: "+
			"\nnetbird service install \nnetbird service start\n", err)
	}
	defer func() {
		err := conn.Close()
		if err != nil {
			log.Warnf("failed closing dameon gRPC client connection %v", err)
			return
		}
	}()

	client := proto.NewDaemonServiceClient(conn)

	status, err := client.Status(ctx, &proto.StatusRequest{})
	if err != nil {
		return fmt.Errorf("unable to get daemon status: %v", err)
	}

	if status.Status == string(internal.StatusConnected) {
		cmd.Println("Already connected")
		return nil
	}

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

		openURL(cmd, loginResp.VerificationURIComplete)

		_, err = client.WaitSSOLogin(ctx, &proto.WaitSSOLoginRequest{UserCode: loginResp.UserCode})
		if err != nil {
			return fmt.Errorf("waiting sso login failed with: %v", err)
		}
	}

	if _, err := client.Up(ctx, &proto.UpRequest{}); err != nil {
		return fmt.Errorf("call service up method: %v", err)
	}
	cmd.Println("Connected")
	return nil
}
