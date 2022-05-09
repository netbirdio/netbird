package cmd

import (
	"context"
	"fmt"
	"github.com/skratchdot/open-golang/open"
	"time"

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
		jwtToken := ""

		// workaround to run without service
		if logFile == "console" {
			config, err := internal.GetConfig(managementURL, adminURL, configPath, preSharedKey)
			if err != nil {
				log.Errorf("get config file: %v", err)
				return err
			}

			if ssoLogin {
				tokenInfo, err := interactiveSSOLogin(ctx, config)
				if err != nil {
					log.Errorf("interactive sso login failed: %v", err)
					return err
				}
				jwtToken = tokenInfo.AccessToken
			}

			err = WithBackOff(func() error {
				return internal.Login(ctx, config, setupKey, jwtToken)
			})
			if err != nil {
				log.Errorf("backoff cycle failed: %v", err)
			}
			return err
		}

		if setupKey == "" && !ssoLogin {
			log.Error("setup key can't be empty")
			return fmt.Errorf("empty setup key")
		}

		conn, err := DialClientGRPCServer(ctx, daemonAddr)
		if err != nil {
			log.Errorf("failed to connect to service CLI interface %v", err)
			return err
		}
		defer conn.Close()

		client := proto.NewDaemonServiceClient(conn)

		status, err := client.Status(ctx, &proto.StatusRequest{})
		if err != nil {
			log.Errorf("unable to get daemon status: %v", err)
			return err
		}

		if ssoLogin && status.Status == string(internal.StatusNeedsLogin) {
			tokenInfo, err := nonInteractiveSSOLogin(ctx, client)
			if err != nil {
				log.Errorf("interactive sso login failed: %v", err)
				return err
			}
			jwtToken = tokenInfo.AccessToken
		}

		request := proto.LoginRequest{
			SetupKey:      setupKey,
			PreSharedKey:  preSharedKey,
			ManagementUrl: managementURL,
			JwtToken:      jwtToken,
		}

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

func interactiveSSOLogin(ctx context.Context, config *internal.Config) (*internal.TokenInfo, error) {

	providerConfig, err := internal.GetDeviceAuthorizationFlowInfo(ctx, config)
	if err != nil {
		log.Errorf("getting device authorization flow info failed with error: %v", err)
		return nil, err
	}

	hostedClient := internal.NewHostedDeviceFlow(
		providerConfig.ProviderConfig.Audience,
		providerConfig.ProviderConfig.ClientID,
		providerConfig.ProviderConfig.Domain,
	)

	flowInfo, err := hostedClient.RequestDeviceCode(context.TODO())
	if err != nil {
		log.Errorf("getting a request device code failed: %v", err)
		return nil, err
	}

	openURL(flowInfo.VerificationURI, flowInfo.VerificationURIComplete, flowInfo.UserCode)

	waitTimeout := time.Duration(flowInfo.ExpiresIn)
	waitCTX, c := context.WithTimeout(context.TODO(), waitTimeout*time.Second)
	defer c()

	tokenInfo, err := hostedClient.WaitToken(waitCTX, flowInfo)
	if err != nil {
		log.Errorf("waiting for browser login failed: %v", err)
		return nil, err
	}

	return &tokenInfo, nil
}

func nonInteractiveSSOLogin(ctx context.Context, client proto.DaemonServiceClient) (*internal.TokenInfo, error) {

	cfg, err := client.GetConfig(ctx, &proto.GetConfigRequest{})
	if err != nil {
		log.Errorf("get config settings from server: %v", err)
		return nil, err
	}

	providerConfig := cfg.DeviceAuthorizationFlow.GetProviderConfig()

	hostedClient := internal.NewHostedDeviceFlow(
		providerConfig.Audience,
		providerConfig.ClientID,
		providerConfig.Domain,
	)

	flowInfo, err := hostedClient.RequestDeviceCode(context.TODO())
	if err != nil {
		log.Errorf("getting a request device code failed: %v", err)
		return nil, err
	}

	openURL(flowInfo.VerificationURI, flowInfo.VerificationURIComplete, flowInfo.UserCode)

	waitTimeout := time.Duration(flowInfo.ExpiresIn)
	waitCTX, c := context.WithTimeout(context.TODO(), waitTimeout*time.Second)
	defer c()

	tokenInfo, err := hostedClient.WaitToken(waitCTX, flowInfo)
	if err != nil {
		log.Errorf("waiting for browser login failed: %v", err)
		return nil, err
	}

	return &tokenInfo, nil
}

func openURL(verificationURI, verificationURIComplete, userCode string) {
	err := open.Run(verificationURIComplete)
	if err != nil {
		fmt.Println("Unable to open the default browser.")
		fmt.Println("If this is not an interactive shell, you may want to use the setup key, see https://www.netbird.io/docs/overview/setup-keys")
		fmt.Printf("Otherwise, you can continue the login flow by accessing the url below:\n\t%s\n", verificationURI)
		fmt.Printf("Use the access code: %s\n", userCode)
		fmt.Printf("Or press CTRL + C or COMMAND + C")
	}
}
