package android

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/auth"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/mobile"
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
//
// The configuration at cfgPath is reused when one is already there, and only created when it is
// not. Building a fresh in-memory config unconditionally gives the client a new WireGuard key on
// every call: the peer registers under that key, the key is written out, and any peer registered by
// an earlier call is orphaned on the server. It also breaks a client that enrols and then runs from
// the persisted config, because the identity it registered is not the one it runs with — the
// management stream rejects it with "no peer auth method provided".
func NewAuth(cfgPath string, mgmURL string) (*Auth, error) {
	inputCfg := profilemanager.ConfigInput{
		ConfigPath:    cfgPath,
		ManagementURL: mgmURL,
	}

	cfg, err := profilemanager.UpdateOrCreateConfig(inputCfg)
	if err != nil {
		return nil, err
	}

	return &Auth{
		ctx:     context.Background(),
		config:  cfg,
		cfgPath: cfgPath,
	}, nil
}

// NewAuthWithConfig instantiate Auth based on existing config. cfgPath is the
// file the config was loaded from; it identifies the profile whose account email
// backs the login_hint.
func NewAuthWithConfig(ctx context.Context, config *profilemanager.Config, cfgPath string) *Auth {
	return &Auth{
		ctx:     ctx,
		config:  config,
		cfgPath: cfgPath,
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
	email := ""
	if needsLogin {
		tokenInfo, err := a.foregroundGetTokenInfo(authClient, urlOpener, isAndroidTV)
		if err != nil {
			return fmt.Errorf("interactive sso login failed: %v", err)
		}
		jwtToken = tokenInfo.GetTokenToUse()
		email = tokenInfo.Email
	}

	err, _ = authClient.Login(a.ctx, "", jwtToken)
	if err != nil {
		return fmt.Errorf("login failed: %v", err)
	}

	// Stored after Login, not before: a rejected token must not leave a hint
	// pointing at an account that cannot be used.
	if email != "" && a.cfgPath != "" {
		if err := mobile.WriteProfileEmail(a.cfgPath, email); err != nil {
			log.Warnf("failed to store profile account email: %v", err)
		}
	}

	go urlOpener.OnLoginSuccess()

	return nil
}

func (a *Auth) foregroundGetTokenInfo(authClient *auth.Auth, urlOpener URLOpener, isAndroidTV bool) (*auth.TokenInfo, error) {
	oAuthFlow, err := authClient.GetOAuthFlow(a.ctx, isAndroidTV, profileLoginHint(a.cfgPath))
	if err != nil {
		return nil, fmt.Errorf("failed to get OAuth flow: %v", err)
	}

	return runOAuthFlow(a.ctx, oAuthFlow, urlOpener, nil)
}

// profileLoginHint returns the stored account email for the profile at cfgPath.
// An empty hint is deliberate, not a fallback: a fresh profile leaves the
// choice to the IdP. Switching accounts is done by switching or removing
// profiles, not by logging out — logout keeps the email.
func profileLoginHint(cfgPath string) string {
	if cfgPath == "" {
		return ""
	}
	return mobile.ReadProfileEmail(cfgPath)
}

// runOAuthFlow drives an already acquired OAuth flow to a token: requests the
// flow info, presents the verification URL through the opener and waits for
// the browser round-trip. Open is called synchronously — it is what marks the
// surface as opened on the client side, and a fast token's OnLoginSuccess is
// a no-op until it has, so the dismissal would be dropped rather than
// delayed. Openers must therefore not block: they post their UI work and
// return. onWaiting, when set, runs after the URL is shown, right before the
// blocking wait.
func runOAuthFlow(ctx context.Context, flow auth.OAuthFlow, urlOpener URLOpener, onWaiting func()) (*auth.TokenInfo, error) {
	flowInfo, err := flow.RequestAuthInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("request auth info: %w", err)
	}

	urlOpener.Open(flowInfo.VerificationURIComplete, flowInfo.UserCode)

	if onWaiting != nil {
		onWaiting()
	}

	tokenInfo, err := flow.WaitToken(ctx, flowInfo)
	if err != nil {
		return nil, fmt.Errorf("wait for token: %w", err)
	}

	return &tokenInfo, nil
}
