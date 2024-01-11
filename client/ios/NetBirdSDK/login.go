package NetBirdSDK

import (
	"context"
	"fmt"
	"time"

	"github.com/cenkalti/backoff/v4"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/cmd"
	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/system"
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
func (a *Auth) SaveConfigIfSSOSupported() (bool, error) {
	supportsSSO := true
	err := a.withBackOff(a.ctx, func() (err error) {
		_, err = internal.GetDeviceAuthorizationFlowInfo(a.ctx, a.config.PrivateKey, a.config.ManagementURL)
		if s, ok := gstatus.FromError(err); ok && (s.Code() == codes.NotFound || s.Code() == codes.Unimplemented) {
			_, err = internal.GetPKCEAuthorizationFlowInfo(a.ctx, a.config.PrivateKey, a.config.ManagementURL)
			if s, ok := gstatus.FromError(err); ok && (s.Code() == codes.NotFound || s.Code() == codes.Unimplemented) {
				supportsSSO = false
				err = nil
			}

			return err
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
func (a *Auth) LoginWithSetupKeyAndSaveConfig(setupKey string, deviceName string) error {
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

func (a *Auth) Login() error {
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
		return fmt.Errorf("Not authenticated")
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

func (a *Auth) withBackOff(ctx context.Context, bf func() error) error {
	return backoff.RetryNotify(
		bf,
		backoff.WithContext(cmd.CLIBackOffSettings, ctx),
		func(err error, duration time.Duration) {
			log.Warnf("retrying Login to the Management service in %v due to error %v", duration, err)
		})
}
