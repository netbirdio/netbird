package android

import (
	"context"
	"fmt"

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
	authClient, err := auth.NewAuth(a.ctx, a.config.PrivateKey, a.config.ManagementURL, a.config)
	if err != nil {
		return false, fmt.Errorf("failed to create auth client: %v", err)
	}
	defer authClient.Close()

	supportsSSO, err := authClient.IsSSOSupported(a.ctx)
	if err != nil {
		return false, fmt.Errorf("failed to check SSO support: %v", err)
	}

	if !supportsSSO {
		return false, nil
	}

	err = profilemanager.WriteOutConfig(a.cfgPath, a.config)
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
	authClient, err := auth.NewAuth(a.ctx, a.config.PrivateKey, a.config.ManagementURL, a.config)
	if err != nil {
		return fmt.Errorf("failed to create auth client: %v", err)
	}
	defer authClient.Close()

	//nolint
	ctxWithValues := context.WithValue(a.ctx, system.DeviceNameCtxKey, deviceName)
	err, _ = authClient.Login(ctxWithValues, setupKey, "")
	if err != nil {
		return fmt.Errorf("login failed: %v", err)
	}

	return profilemanager.WriteOutConfig(a.cfgPath, a.config)
}

// Login try register the client on the server
func (a *Auth) Login(resultListener ErrListener, urlOpener URLOpener, isAndroidTV bool) {
	go func() {
		err := a.login(urlOpener, isAndroidTV)
		if err != nil {
			resultListener.OnError(err)
		} else {
			resultListener.OnSuccess()
		}
	}()
}

func (a *Auth) login(urlOpener URLOpener, isAndroidTV bool) error {
	authClient, err := auth.NewAuth(a.ctx, a.config.PrivateKey, a.config.ManagementURL, a.config)
	if err != nil {
		return fmt.Errorf("failed to create auth client: %v", err)
	}
	defer authClient.Close()

	// check if we need to generate JWT token
	needsLogin, err := authClient.IsLoginRequired(a.ctx)
	if err != nil {
		return fmt.Errorf("failed to check login requirement: %v", err)
	}

	jwtToken := ""
	if needsLogin {
		tokenInfo, err := a.foregroundGetTokenInfo(authClient, urlOpener, isAndroidTV)
		if err != nil {
			return fmt.Errorf("interactive sso login failed: %v", err)
		}
		jwtToken = tokenInfo.GetTokenToUse()
	}

	err, _ = authClient.Login(a.ctx, "", jwtToken)
	if err != nil {
		return fmt.Errorf("login failed: %v", err)
	}

	go urlOpener.OnLoginSuccess()

	return nil
}

func (a *Auth) foregroundGetTokenInfo(authClient *auth.Auth, urlOpener URLOpener, isAndroidTV bool) (*auth.TokenInfo, error) {
	oAuthFlow, err := authClient.GetOAuthFlow(a.ctx, isAndroidTV)
	if err != nil {
		return nil, fmt.Errorf("failed to get OAuth flow: %v", err)
	}

	flowInfo, err := oAuthFlow.RequestAuthInfo(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("getting a request OAuth flow info failed: %v", err)
	}

	go urlOpener.Open(flowInfo.VerificationURIComplete, flowInfo.UserCode)

	tokenInfo, err := oAuthFlow.WaitToken(a.ctx, flowInfo)
	if err != nil {
		return nil, fmt.Errorf("waiting for browser login failed: %v", err)
	}

	return &tokenInfo, nil
}
