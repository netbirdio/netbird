package auth

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/ssh"
	"github.com/netbirdio/netbird/client/system"
	mgm "github.com/netbirdio/netbird/shared/management/client"
	"github.com/netbirdio/netbird/shared/management/client/common"
)

// Auth manages authentication operations with the management server
// The underlying management client handles connection retry and reconnection automatically
type Auth struct {
	client *mgm.GrpcClient
	config *profilemanager.Config
}

// NewAuth creates a new Auth instance that manages authentication flows
// It establishes a connection to the management server that will be reused for all operations
// The management client handles connection retry and reconnection automatically
func NewAuth(ctx context.Context, privateKey string, mgmURL *url.URL, config *profilemanager.Config) (*Auth, error) {
	// Validate WireGuard private key
	myPrivateKey, err := wgtypes.ParseKey(privateKey)
	if err != nil {
		log.Errorf("failed parsing Wireguard key %s: [%s]", privateKey, err.Error())
		return nil, err
	}

	// Determine TLS setting based on URL scheme
	mgmTLSEnabled := mgmURL.Scheme == "https"

	log.Debugf("connecting to Management Service %s", mgmURL.String())
	mgmClient := mgm.NewClient(mgmURL.Host, myPrivateKey, mgmTLSEnabled)
	if err := mgmClient.Connect(ctx); err != nil {
		log.Errorf("failed connecting to Management Service %s: %v", mgmURL.String(), err)
		return nil, err
	}

	log.Debugf("connected to the Management service %s", mgmURL.String())

	return &Auth{
		client: mgmClient,
		config: config,
	}, nil
}

// Close closes the management client connection
func (a *Auth) Close() error {
	if a.client == nil {
		return nil
	}
	return a.client.Close()
}

// IsSSOSupported checks if the management server supports SSO by attempting to retrieve auth flow configurations.
// Returns true if either PKCE or Device authorization flow is supported, false otherwise.
func (a *Auth) IsSSOSupported(ctx context.Context) (bool, error) {
	// Try PKCE flow first
	_, err := a.getPKCEFlow(ctx)
	if err == nil {
		return true, nil
	}

	// Check if PKCE is not supported
	if errors.Is(err, mgm.ErrNotFound) || errors.Is(err, mgm.ErrUnimplemented) {
		// PKCE not supported, try Device flow
		_, err = a.getDeviceFlow(ctx)
		if err == nil {
			return true, nil
		}

		// Check if Device flow is also not supported
		if errors.Is(err, mgm.ErrNotFound) || errors.Is(err, mgm.ErrUnimplemented) {
			// Neither PKCE nor Device flow is supported
			return false, nil
		}

		// Device flow check returned an error other than NotFound/Unimplemented
		return false, err
	}

	// PKCE flow check returned an error other than NotFound/Unimplemented
	return false, err
}

// IsLoginRequired checks if login is required by attempting to authenticate with the server
func (a *Auth) IsLoginRequired(ctx context.Context) (bool, error) {
	pubSSHKey, err := ssh.GeneratePublicKey([]byte(a.config.SSHKey))
	if err != nil {
		return false, err
	}

	err = a.doMgmLogin(ctx, pubSSHKey)
	if isLoginNeeded(err) {
		return true, nil
	}

	return false, err
}

// Login attempts to log in or register the client with the management server
// Returns custom errors from mgm package: ErrPermissionDenied, ErrInvalidArgument, ErrUnauthenticated
func (a *Auth) Login(ctx context.Context, setupKey string, jwtToken string) error {
	pubSSHKey, err := ssh.GeneratePublicKey([]byte(a.config.SSHKey))
	if err != nil {
		return fmt.Errorf("generate SSH public key: %w", err)
	}

	err = a.doMgmLogin(ctx, pubSSHKey)
	if isRegistrationNeeded(err) {
		log.Debugf("peer registration required")
		return a.registerPeer(ctx, setupKey, jwtToken, pubSSHKey)
	}
	return err
}

// getPKCEFlow retrieves PKCE authorization flow configuration and creates a flow instance
func (a *Auth) getPKCEFlow(ctx context.Context) (*PKCEAuthorizationFlow, error) {
	protoFlow, err := a.client.GetPKCEAuthorizationFlow(ctx)
	if err != nil {
		if errors.Is(err, mgm.ErrNotFound) {
			log.Warnf("server couldn't find pkce flow, contact admin: %v", err)
			return nil, err
		}
		log.Errorf("failed to retrieve pkce flow: %v", err)
		return nil, err
	}

	protoConfig := protoFlow.GetProviderConfig()
	config := &PKCEAuthProviderConfig{
		Audience:              protoConfig.GetAudience(),
		ClientID:              protoConfig.GetClientID(),
		ClientSecret:          protoConfig.GetClientSecret(),
		TokenEndpoint:         protoConfig.GetTokenEndpoint(),
		AuthorizationEndpoint: protoConfig.GetAuthorizationEndpoint(),
		Scope:                 protoConfig.GetScope(),
		RedirectURLs:          protoConfig.GetRedirectURLs(),
		UseIDToken:            protoConfig.GetUseIDToken(),
		ClientCertPair:        a.config.ClientCertKeyPair,
		DisablePromptLogin:    protoConfig.GetDisablePromptLogin(),
		LoginFlag:             common.LoginFlag(protoConfig.GetLoginFlag()),
	}

	if err := validatePKCEConfig(config); err != nil {
		return nil, err
	}

	flow, err := NewPKCEAuthorizationFlow(*config)
	if err != nil {
		return nil, err
	}

	return flow, nil
}

// getDeviceFlow retrieves device authorization flow configuration and creates a flow instance
func (a *Auth) getDeviceFlow(ctx context.Context) (*DeviceAuthorizationFlow, error) {
	protoFlow, err := a.client.GetDeviceAuthorizationFlow(ctx)
	if err != nil {
		if errors.Is(err, mgm.ErrNotFound) {
			log.Warnf("server couldn't find device flow, contact admin: %v", err)
			return nil, err
		}
		log.Errorf("failed to retrieve device flow: %v", err)
		return nil, err
	}

	protoConfig := protoFlow.GetProviderConfig()
	config := &DeviceAuthProviderConfig{
		Audience:           protoConfig.GetAudience(),
		ClientID:           protoConfig.GetClientID(),
		ClientSecret:       protoConfig.GetClientSecret(),
		Domain:             protoConfig.Domain,
		TokenEndpoint:      protoConfig.GetTokenEndpoint(),
		DeviceAuthEndpoint: protoConfig.GetDeviceAuthEndpoint(),
		Scope:              protoConfig.GetScope(),
		UseIDToken:         protoConfig.GetUseIDToken(),
	}

	// Keep compatibility with older management versions
	if config.Scope == "" {
		config.Scope = "openid"
	}

	if err := validateDeviceAuthConfig(config); err != nil {
		return nil, err
	}

	flow, err := NewDeviceAuthorizationFlow(*config)
	if err != nil {
		return nil, err
	}

	return flow, nil
}

// doMgmLogin performs the actual login operation with the management service
func (a *Auth) doMgmLogin(ctx context.Context, pubSSHKey []byte) error {
	sysInfo := system.GetInfo(ctx)
	sysInfo.SetFlags(
		a.config.RosenpassEnabled,
		a.config.RosenpassPermissive,
		a.config.ServerSSHAllowed,
		a.config.DisableClientRoutes,
		a.config.DisableServerRoutes,
		a.config.DisableDNS,
		a.config.DisableFirewall,
		a.config.BlockLANAccess,
		a.config.BlockInbound,
		a.config.LazyConnectionEnabled,
		a.config.EnableSSHRoot,
		a.config.EnableSSHSFTP,
		a.config.EnableSSHLocalPortForwarding,
		a.config.EnableSSHRemotePortForwarding,
		a.config.DisableSSHAuth,
	)
	_, err := a.client.Login(ctx, sysInfo, pubSSHKey, a.config.DNSLabels)
	return err
}

// registerPeer checks whether setupKey was provided via cmd line and if not then it prompts user to enter a key.
// Otherwise tries to register with the provided setupKey via command line.
func (a *Auth) registerPeer(ctx context.Context, setupKey string, jwtToken string, pubSSHKey []byte) error {
	validSetupKey, err := uuid.Parse(setupKey)
	if err != nil && jwtToken == "" {
		return fmt.Errorf("%w: invalid setup-key or no SSO information provided: %v", mgm.ErrInvalidArgument, err)
	}

	log.Debugf("sending peer registration request to Management Service")
	info := system.GetInfo(ctx)
	info.SetFlags(
		a.config.RosenpassEnabled,
		a.config.RosenpassPermissive,
		a.config.ServerSSHAllowed,
		a.config.DisableClientRoutes,
		a.config.DisableServerRoutes,
		a.config.DisableDNS,
		a.config.DisableFirewall,
		a.config.BlockLANAccess,
		a.config.BlockInbound,
		a.config.LazyConnectionEnabled,
		a.config.EnableSSHRoot,
		a.config.EnableSSHSFTP,
		a.config.EnableSSHLocalPortForwarding,
		a.config.EnableSSHRemotePortForwarding,
		a.config.DisableSSHAuth,
	)

	// todo: fix error handling of validSetupKey
	if err := a.client.Register(ctx, validSetupKey.String(), jwtToken, info, pubSSHKey, a.config.DNSLabels); err != nil {
		log.Errorf("failed registering peer %v", err)
		return err
	}

	log.Infof("peer has been successfully registered on Management Service")

	return nil
}

// isPermissionDenied checks if the error is a PermissionDenied error
func isPermissionDenied(err error) bool {
	return errors.Is(err, mgm.ErrPermissionDenied)
}

// isLoginNeeded checks if the error indicates login is required
func isLoginNeeded(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, mgm.ErrInvalidArgument) ||
		errors.Is(err, mgm.ErrPermissionDenied) ||
		errors.Is(err, mgm.ErrUnauthenticated)
}

// isRegistrationNeeded checks if the error indicates peer registration is needed
func isRegistrationNeeded(err error) bool {
	return isPermissionDenied(err)
}
