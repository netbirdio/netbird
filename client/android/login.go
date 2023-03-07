package android

import (
	"context"
	"errors"
	"fmt"
	"github.com/cenkalti/backoff/v4"
	"github.com/netbirdio/netbird/client/cmd"
	"time"

	"github.com/netbirdio/netbird/client/internal"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"
)

type UrlOpener interface {
	Open(string)
}

var ErrInvalidURLOpener = errors.New("invalid url opener")

// Auth can register or login new client
type Auth struct {
	ctx       context.Context
	urlOpener UrlOpener
	config    *internal.Config
	cfgPath   string
}

// NewAuth instantiate Auth struct and validate the management URL
func NewAuth(cfgPath string, mgmUrl string) (*Auth, error) {
	inputCfg := internal.ConfigInput{
		ManagementURL: mgmUrl,
	}

	cfg, err := internal.CreateInMemoryConfig(inputCfg)
	if err != nil {
		return nil, err
	}

	return &Auth{
		ctx:     context.Background(),
		config:  cfg,
		cfgPath: cfgPath,
	}, nil
}

// NewAuthWithConfig instantiate Auth based on existing config
func NewAuthWithConfig(ctx context.Context, urlOpener UrlOpener, config *internal.Config) *Auth {
	return &Auth{
		ctx:       ctx,
		urlOpener: urlOpener,
		config:    config,
	}
}

// LoginAndSaveConfigIfSSOSupported test the connectivity with the management server.
// If the SSO is supported than save the configuration. Return with the SSO login is supported or not.
func (a *Auth) LoginAndSaveConfigIfSSOSupported() (bool, error) {
	var needsLogin bool
	err := a.withBackOff(a.ctx, func() (err error) {
		needsLogin, err = internal.IsLoginRequired(a.ctx, a.config.PrivateKey, a.config.ManagementURL, a.config.SSHKey)
		return
	})
	if err != nil {
		return false, fmt.Errorf("backoff cycle failed: %v", err)
	}
	if !needsLogin {
		return false, nil
	}
	err = internal.WriteOutConfig(a.cfgPath, a.config)
	return needsLogin, err
}

// LoginWithSetupKeyAndSaveConfig test the connectivity with the management server with the setup key.
func (a *Auth) LoginWithSetupKeyAndSaveConfig(setupKey string) error {
	err := a.withBackOff(a.ctx, func() error {
		err := internal.Login(a.ctx, a.config, setupKey, "")
		if s, ok := gstatus.FromError(err); ok && (s.Code() == codes.InvalidArgument || s.Code() == codes.PermissionDenied) {
			return nil
		}
		return err
	})
	if err != nil {
		return fmt.Errorf("backoff cycle failed: %v", err)
	}

	return internal.WriteOutConfig(a.cfgPath, a.config)
}

// Login try register the client on the server
func (a *Auth) Login() error {
	if a.urlOpener == nil {
		return ErrInvalidURLOpener
	}
	var needsLogin bool

	// check if we need to generate JWT token
	err := a.withBackOff(a.ctx, func() (err error) {
		needsLogin, err = internal.IsLoginRequired(a.ctx, a.config.PrivateKey, a.config.ManagementURL, a.config.SSHKey)
		return
	})
	if err != nil {
		return fmt.Errorf("backoff cycle failed: %v", err)
	}

	jwtToken := ""
	if needsLogin {
		tokenInfo, err := a.foregroundGetTokenInfo()
		if err != nil {
			return fmt.Errorf("interactive sso login failed: %v", err)
		}
		jwtToken = tokenInfo.AccessToken
	}

	err = a.withBackOff(a.ctx, func() error {
		err := internal.Login(a.ctx, a.config, "", jwtToken)
		if s, ok := gstatus.FromError(err); ok && (s.Code() == codes.InvalidArgument || s.Code() == codes.PermissionDenied) {
			return nil
		}
		return err
	})
	if err != nil {
		return fmt.Errorf("backoff cycle failed: %v", err)
	}

	return nil
}

func (a *Auth) foregroundGetTokenInfo() (*internal.TokenInfo, error) {
	providerConfig, err := internal.GetDeviceAuthorizationFlowInfo(a.ctx, a.config.PrivateKey, a.config.ManagementURL)
	if err != nil {
		s, ok := gstatus.FromError(err)
		if ok && s.Code() == codes.NotFound {
			return nil, fmt.Errorf("no SSO provider returned from management. " +
				"If you are using hosting Netbird see documentation at " +
				"https://github.com/netbirdio/netbird/tree/main/management for details")
		} else if ok && s.Code() == codes.Unimplemented {
			return nil, fmt.Errorf("the management server, %s, does not support SSO providers, "+
				"please update your servver or use Setup Keys to login", a.config.ManagementURL)
		} else {
			return nil, fmt.Errorf("getting device authorization flow info failed with error: %v", err)
		}
	}

	hostedClient := internal.NewHostedDeviceFlow(
		providerConfig.ProviderConfig.Audience,
		providerConfig.ProviderConfig.ClientID,
		providerConfig.ProviderConfig.TokenEndpoint,
		providerConfig.ProviderConfig.DeviceAuthEndpoint,
	)

	flowInfo, err := hostedClient.RequestDeviceCode(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("getting a request device code failed: %v", err)
	}

	go a.urlOpener.Open(flowInfo.VerificationURIComplete)

	waitTimeout := time.Duration(flowInfo.ExpiresIn)
	waitCTX, cancel := context.WithTimeout(a.ctx, waitTimeout*time.Second)
	defer cancel()
	tokenInfo, err := hostedClient.WaitToken(waitCTX, flowInfo)
	if err != nil {
		return nil, fmt.Errorf("waiting for browser login failed: %v", err)
	}

	return &tokenInfo, nil
}

func (a *Auth) withBackOff(ctx context.Context, bf func() error) error {
	return backoff.RetryNotify(
		bf,
		backoff.WithContext(cmd.CLIBackOffSettings, ctx),
		func(err error, duration time.Duration) {
			log.Warnf("retrying Login to the Management service in %v due to error %v", duration, err)
		})
}
