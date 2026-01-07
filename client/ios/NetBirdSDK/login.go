//go:build ios

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
	"github.com/netbirdio/netbird/client/internal/auth"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
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
	Open(url string, userCode string)
	OnLoginSuccess()
}

// Auth can register or login new client
type Auth struct {
	ctx     context.Context
	config  *profilemanager.Config
	cfgPath string
}

// NewAuth instantiate Auth struct and validate the management URL
func NewAuth(cfgPath string, mgmURL string) (*Auth, error) {
	inputCfg := profilemanager.ConfigInput{
		ManagementURL: mgmURL,
	}

	cfg, err := profilemanager.CreateInMemoryConfig(inputCfg)
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
func NewAuthWithConfig(ctx context.Context, config *profilemanager.Config) *Auth {
	return &Auth{
		ctx:    ctx,
		config: config,
	}
}

// SaveConfigIfSSOSupported test the connectivity with the management server by retrieving the server device flow info.
// If it returns a flow info than save the configuration and return true. If it gets a codes.NotFound, it means that SSO
// is not supported and returns false without saving the configuration. For other errors return false.
func (a *Auth) SaveConfigIfSSOSupported(listener SSOListener) {
	if listener == nil {
		log.Errorf("SaveConfigIfSSOSupported: listener is nil")
		return
	}
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
		_, err = internal.GetPKCEAuthorizationFlowInfo(a.ctx, a.config.PrivateKey, a.config.ManagementURL, nil)
		if s, ok := gstatus.FromError(err); ok && (s.Code() == codes.NotFound || s.Code() == codes.Unimplemented) {
			_, err = internal.GetDeviceAuthorizationFlowInfo(a.ctx, a.config.PrivateKey, a.config.ManagementURL)
			s, ok := gstatus.FromError(err)
			if !ok {
				return err
			}
			if s.Code() == codes.NotFound || s.Code() == codes.Unimplemented {
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

	// Use DirectWriteOutConfig to avoid atomic file operations (temp file + rename)
	// which are blocked by the tvOS sandbox in App Group containers
	err = profilemanager.DirectWriteOutConfig(a.cfgPath, a.config)
	return true, err
}

// LoginWithSetupKeyAndSaveConfig test the connectivity with the management server with the setup key.
func (a *Auth) LoginWithSetupKeyAndSaveConfig(resultListener ErrListener, setupKey string, deviceName string) {
	if resultListener == nil {
		log.Errorf("LoginWithSetupKeyAndSaveConfig: resultListener is nil")
		return
	}
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

	// Use DirectWriteOutConfig to avoid atomic file operations (temp file + rename)
	// which are blocked by the tvOS sandbox in App Group containers
	return profilemanager.DirectWriteOutConfig(a.cfgPath, a.config)
}

// LoginSync performs a synchronous login check without UI interaction
// Used for background VPN connection where user should already be authenticated
func (a *Auth) LoginSync() error {
	var needsLogin bool

	// check if we need to generate JWT token
	err := a.withBackOff(a.ctx, func() (err error) {
		needsLogin, err = internal.IsLoginRequired(a.ctx, a.config)
		return
	})
	if err != nil {
		return fmt.Errorf("backoff cycle failed: %v", err)
	}

	jwtToken := ""
	if needsLogin {
		return fmt.Errorf("not authenticated")
	}

	err = a.withBackOff(a.ctx, func() error {
		err := internal.Login(a.ctx, a.config, "", jwtToken)
		if s, ok := gstatus.FromError(err); ok && (s.Code() == codes.PermissionDenied) {
			// PermissionDenied means registration is required or peer is blocked
			return backoff.Permanent(err)
		}
		return err
	})
	if err != nil {
		return fmt.Errorf("login failed: %v", err)
	}

	return nil
}

// Login performs interactive login with device authentication support
// Deprecated: Use LoginWithDeviceName instead to ensure proper device naming on tvOS
func (a *Auth) Login(resultListener ErrListener, urlOpener URLOpener, forceDeviceAuth bool) {
	// Use empty device name - system will use hostname as fallback
	a.LoginWithDeviceName(resultListener, urlOpener, forceDeviceAuth, "")
}

// LoginWithDeviceName performs interactive login with device authentication support
// The deviceName parameter allows specifying a custom device name (required for tvOS)
func (a *Auth) LoginWithDeviceName(resultListener ErrListener, urlOpener URLOpener, forceDeviceAuth bool, deviceName string) {
	if resultListener == nil {
		log.Errorf("LoginWithDeviceName: resultListener is nil")
		return
	}
	if urlOpener == nil {
		log.Errorf("LoginWithDeviceName: urlOpener is nil")
		resultListener.OnError(fmt.Errorf("urlOpener is nil"))
		return
	}
	go func() {
		err := a.login(urlOpener, forceDeviceAuth, deviceName)
		if err != nil {
			resultListener.OnError(err)
		} else {
			resultListener.OnSuccess()
		}
	}()
}

func (a *Auth) login(urlOpener URLOpener, forceDeviceAuth bool, deviceName string) error {
	var needsLogin bool

	// Create context with device name if provided
	ctx := a.ctx
	if deviceName != "" {
		//nolint:staticcheck
		ctx = context.WithValue(a.ctx, system.DeviceNameCtxKey, deviceName)
	}

	// check if we need to generate JWT token
	err := a.withBackOff(ctx, func() (err error) {
		needsLogin, err = internal.IsLoginRequired(ctx, a.config)
		return
	})
	if err != nil {
		return fmt.Errorf("backoff cycle failed: %v", err)
	}

	jwtToken := ""
	if needsLogin {
		tokenInfo, err := a.foregroundGetTokenInfo(urlOpener, forceDeviceAuth)
		if err != nil {
			return fmt.Errorf("interactive sso login failed: %v", err)
		}
		jwtToken = tokenInfo.GetTokenToUse()
	}

	err = a.withBackOff(ctx, func() error {
		err := internal.Login(ctx, a.config, "", jwtToken)
		if s, ok := gstatus.FromError(err); ok && (s.Code() == codes.PermissionDenied) {
			// PermissionDenied means registration is required or peer is blocked
			return backoff.Permanent(err)
		}
		return err
	})
	if err != nil {
		return fmt.Errorf("login failed: %v", err)
	}

	// Save the config before notifying success to ensure persistence completes
	// before the callback potentially triggers teardown on the Swift side.
	// Note: This differs from Android which doesn't save config after login.
	// On iOS/tvOS, we save here because:
	// 1. The config may have been modified during login (e.g., new tokens)
	// 2. On tvOS, the Network Extension context may be the only place with
	//    write permissions to the App Group container
	if a.cfgPath != "" {
		if err := profilemanager.DirectWriteOutConfig(a.cfgPath, a.config); err != nil {
			log.Warnf("failed to save config after login: %v", err)
		}
	}

	// Notify caller of successful login synchronously before returning
	urlOpener.OnLoginSuccess()

	return nil
}

const authInfoRequestTimeout = 30 * time.Second

func (a *Auth) foregroundGetTokenInfo(urlOpener URLOpener, forceDeviceAuth bool) (*auth.TokenInfo, error) {
	oAuthFlow, err := auth.NewOAuthFlow(a.ctx, a.config, false, forceDeviceAuth, "")
	if err != nil {
		return nil, err
	}

	// Use a bounded timeout for the auth info request to prevent indefinite hangs
	authInfoCtx, authInfoCancel := context.WithTimeout(a.ctx, authInfoRequestTimeout)
	defer authInfoCancel()

	flowInfo, err := oAuthFlow.RequestAuthInfo(authInfoCtx)
	if err != nil {
		return nil, fmt.Errorf("getting a request OAuth flow info failed: %v", err)
	}

	urlOpener.Open(flowInfo.VerificationURIComplete, flowInfo.UserCode)

	waitTimeout := time.Duration(flowInfo.ExpiresIn) * time.Second
	waitCTX, cancel := context.WithTimeout(a.ctx, waitTimeout)
	defer cancel()
	tokenInfo, err := oAuthFlow.WaitToken(waitCTX, flowInfo)
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

// GetConfigJSON returns the current config as a JSON string.
// This can be used by the caller to persist the config via alternative storage
// mechanisms (e.g., UserDefaults on tvOS where file writes are blocked).
func (a *Auth) GetConfigJSON() (string, error) {
	if a.config == nil {
		return "", fmt.Errorf("no config available")
	}
	return profilemanager.ConfigToJSON(a.config)
}

// SetConfigFromJSON loads config from a JSON string.
// This can be used to restore config from alternative storage mechanisms.
func (a *Auth) SetConfigFromJSON(jsonStr string) error {
	cfg, err := profilemanager.ConfigFromJSON(jsonStr)
	if err != nil {
		return err
	}
	a.config = cfg
	return nil
}
