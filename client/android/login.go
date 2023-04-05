package android

import (
	"context"
	"fmt"
	"time"

	"github.com/cenkalti/backoff/v4"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/cmd"
	"github.com/netbirdio/netbird/client/system"

	"github.com/netbirdio/netbird/client/internal"
)

// SSOListener is async listener for mobile framework
type SSOListener interface {
	OnSuccess(bool)
	OnError(error)
}

// ErrListener is async listener for mobile framework
type ErrListener interface {
	OnSuccess()
	OnError(error)
}

// URLOpener it is a callback interface. The Open function will be triggered if
// the backend want to show an url for the user
type URLOpener interface {
	Open(string)
}

// Auth can register or login new client
type Auth struct {
	ctx     context.Context
	config  *internal.Config
	cfgPath string
}

// NewAuth instantiate Auth struct and validate the management URL
func NewAuth(cfgPath string, mgmURL string) (*Auth, error) {
	inputCfg := internal.ConfigInput{
		ManagementURL: mgmURL,
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
func NewAuthWithConfig(ctx context.Context, config *internal.Config) *Auth {
	return &Auth{
		ctx:    ctx,
		config: config,
	}
}

// SaveConfigIfSSOSupported test the connectivity with the management server by retrieving the server device flow info.
// If it returns a flow info than save the configuration and return true. If it gets a codes.NotFound, it means that SSO
// is not supported and returns false without saving the configuration. For other errors return false.
func (a *Auth) SaveConfigIfSSOSupported(listener SSOListener) {
	go func() {
		sso, err := a.saveConfigIfSSOSupported()
		if err != nil {
			listener.OnError(err)
		} else {
			listener.OnSuccess(sso)
		}
	}()
}

func (a *Auth) saveConfigIfSSOSupported() (bool, error) {
	supportsSSO := true
	err := a.withBackOff(a.ctx, func() (err error) {
		_, err = internal.GetDeviceAuthorizationFlowInfo(a.ctx, a.config.PrivateKey, a.config.ManagementURL)
		if s, ok := gstatus.FromError(err); ok && s.Code() == codes.NotFound {
			supportsSSO = false
			err = nil
		}
		return err
	})

	if !supportsSSO {
		return false, nil
	}

	if err != nil {
		return false, fmt.Errorf("backoff cycle failed: %v", err)
	}

	err = internal.WriteOutConfig(a.cfgPath, a.config)
	return true, err
}

// LoginWithSetupKeyAndSaveConfig test the connectivity with the management server with the setup key.
func (a *Auth) LoginWithSetupKeyAndSaveConfig(resultListener ErrListener, setupKey string, deviceName string) {
	go func() {
		err := a.loginWithSetupKeyAndSaveConfig(setupKey, deviceName)
		if err != nil {
			resultListener.OnError(err)
		} else {
			resultListener.OnSuccess()
		}
	}()
}

func (a *Auth) loginWithSetupKeyAndSaveConfig(setupKey string, deviceName string) error {
	//nolint
	ctxWithValues := context.WithValue(a.ctx, system.DeviceNameCtxKey, deviceName)

	err := a.withBackOff(a.ctx, func() error {
		backoffErr := internal.Login(ctxWithValues, a.config, setupKey, "")
		if s, ok := gstatus.FromError(backoffErr); ok && (s.Code() == codes.PermissionDenied) {
			// we got an answer from management, exit backoff earlier
			return backoff.Permanent(backoffErr)
		}
		return backoffErr
	})
	if err != nil {
		return fmt.Errorf("backoff cycle failed: %v", err)
	}

	return internal.WriteOutConfig(a.cfgPath, a.config)
}

// Login try register the client on the server
func (a *Auth) Login(resultListener ErrListener, urlOpener URLOpener) {
	go func() {
		err := a.login(urlOpener)
		if err != nil {
			resultListener.OnError(err)
		} else {
			resultListener.OnSuccess()
		}
	}()
}

func (a *Auth) login(urlOpener URLOpener) error {
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
		tokenInfo, err := a.foregroundGetTokenInfo(urlOpener)
		if err != nil {
			return fmt.Errorf("interactive sso login failed: %v", err)
		}
		jwtToken = tokenInfo.GetTokenToUse()
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

func (a *Auth) foregroundGetTokenInfo(urlOpener URLOpener) (*internal.TokenInfo, error) {
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

	hostedClient := internal.NewHostedDeviceFlow(providerConfig.ProviderConfig)

	flowInfo, err := hostedClient.RequestDeviceCode(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("getting a request device code failed: %v", err)
	}

	go urlOpener.Open(flowInfo.VerificationURIComplete)

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
