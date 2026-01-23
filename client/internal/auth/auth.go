package auth

import (
	"context"
	"net/url"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/ssh"
	"github.com/netbirdio/netbird/client/system"
	mgm "github.com/netbirdio/netbird/shared/management/client"
	"github.com/netbirdio/netbird/shared/management/client/common"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

// Auth manages authentication operations with the management server
// It maintains a long-lived connection and automatically handles reconnection with backoff
type Auth struct {
	mutex         sync.RWMutex
	client        *mgm.GrpcClient
	config        *profilemanager.Config
	privateKey    wgtypes.Key
	mgmURL        *url.URL
	mgmTLSEnabled bool
}

// NewAuth creates a new Auth instance that manages authentication flows
// It establishes a connection to the management server that will be reused for all operations
// The connection is automatically recreated with backoff if it becomes disconnected
func NewAuth(ctx context.Context, privateKey string, mgmURL *url.URL, config *profilemanager.Config) (*Auth, error) {
	// Validate WireGuard private key
	myPrivateKey, err := wgtypes.ParseKey(privateKey)
	if err != nil {
		return nil, err
	}

	// Determine TLS setting based on URL scheme
	mgmTLSEnabled := mgmURL.Scheme == "https"

	log.Debugf("connecting to Management Service %s", mgmURL.String())
	mgmClient, err := mgm.NewClient(ctx, mgmURL.Host, myPrivateKey, mgmTLSEnabled)
	if err != nil {
		log.Errorf("failed connecting to Management Service %s: %v", mgmURL.String(), err)
		return nil, err
	}

	log.Debugf("connected to the Management service %s", mgmURL.String())

	return &Auth{
		client:        mgmClient,
		config:        config,
		privateKey:    myPrivateKey,
		mgmURL:        mgmURL,
		mgmTLSEnabled: mgmTLSEnabled,
	}, nil
}

// Close closes the management client connection
func (a *Auth) Close() error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	if a.client == nil {
		return nil
	}
	return a.client.Close()
}

// IsSSOSupported checks if the management server supports SSO by attempting to retrieve auth flow configurations.
// Returns true if either PKCE or Device authorization flow is supported, false otherwise.
// This function encapsulates the SSO detection logic to avoid exposing gRPC error codes to upper layers.
// Automatically retries with backoff and reconnection on connection errors.
func (a *Auth) IsSSOSupported(ctx context.Context) (bool, error) {
	var supportsSSO bool

	err := a.withRetry(ctx, func(client *mgm.GrpcClient) error {
		// Try PKCE flow first
		_, err := a.getPKCEFlow(client)
		if err == nil {
			supportsSSO = true
			return nil
		}

		// Check if PKCE is not supported
		if s, ok := status.FromError(err); ok && (s.Code() == codes.NotFound || s.Code() == codes.Unimplemented) {
			// PKCE not supported, try Device flow
			_, err = a.getDeviceFlow(client)
			if err == nil {
				supportsSSO = true
				return nil
			}

			// Check if Device flow is also not supported
			if s, ok := status.FromError(err); ok && (s.Code() == codes.NotFound || s.Code() == codes.Unimplemented) {
				// Neither PKCE nor Device flow is supported
				supportsSSO = false
				return nil
			}

			// Device flow check returned an error other than NotFound/Unimplemented
			return err
		}

		// PKCE flow check returned an error other than NotFound/Unimplemented
		return err
	})

	return supportsSSO, err
}

// GetOAuthFlow returns an OAuth flow (PKCE or Device) using the existing management connection
// This avoids creating a new connection to the management server
func (a *Auth) GetOAuthFlow(ctx context.Context, forceDeviceAuth bool) (OAuthFlow, error) {
	var flow OAuthFlow
	var err error

	err = a.withRetry(ctx, func(client *mgm.GrpcClient) error {
		if forceDeviceAuth {
			flow, err = a.getDeviceFlow(client)
			return err
		}

		// Try PKCE flow first
		flow, err = a.getPKCEFlow(client)
		if err != nil {
			// If PKCE not supported, try Device flow
			if s, ok := status.FromError(err); ok && (s.Code() == codes.NotFound || s.Code() == codes.Unimplemented) {
				flow, err = a.getDeviceFlow(client)
				return err
			}
			return err
		}
		return nil
	})

	return flow, err
}

// IsLoginRequired checks if login is required by attempting to authenticate with the server
// Automatically retries with backoff and reconnection on connection errors.
func (a *Auth) IsLoginRequired(ctx context.Context) (bool, error) {
	pubSSHKey, err := ssh.GeneratePublicKey([]byte(a.config.SSHKey))
	if err != nil {
		return false, err
	}

	var needsLogin bool

	err = a.withRetry(ctx, func(client *mgm.GrpcClient) error {
		_, _, err := a.doMgmLogin(client, ctx, pubSSHKey)
		if isLoginNeeded(err) {
			needsLogin = true
			return nil
		}
		needsLogin = false
		return err
	})

	return needsLogin, err
}

// Login attempts to log in or register the client with the management server
// Returns error and a boolean indicating if it's an authentication error (permission denied) that should stop retries.
// Automatically retries with backoff and reconnection on connection errors.
func (a *Auth) Login(ctx context.Context, setupKey string, jwtToken string) (error, bool) {
	pubSSHKey, err := ssh.GeneratePublicKey([]byte(a.config.SSHKey))
	if err != nil {
		return err, false
	}

	var isAuthError bool

	err = a.withRetry(ctx, func(client *mgm.GrpcClient) error {
		serverKey, _, err := a.doMgmLogin(client, ctx, pubSSHKey)
		if serverKey != nil && isRegistrationNeeded(err) {
			log.Debugf("peer registration required")
			_, err = a.registerPeer(client, ctx, setupKey, jwtToken, pubSSHKey)
			if err != nil {
				isAuthError = isPermissionDenied(err)
				return err
			}
		} else if err != nil {
			isAuthError = isPermissionDenied(err)
			return err
		}

		isAuthError = false
		return nil
	})

	return err, isAuthError
}

// getPKCEFlow retrieves PKCE authorization flow configuration and creates a flow instance
func (a *Auth) getPKCEFlow(client *mgm.GrpcClient) (*PKCEAuthorizationFlow, error) {
	serverKey, err := client.GetServerPublicKey()
	if err != nil {
		log.Errorf("failed while getting Management Service public key: %v", err)
		return nil, err
	}

	protoFlow, err := client.GetPKCEAuthorizationFlow(*serverKey)
	if err != nil {
		if s, ok := status.FromError(err); ok && s.Code() == codes.NotFound {
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
func (a *Auth) getDeviceFlow(client *mgm.GrpcClient) (*DeviceAuthorizationFlow, error) {
	serverKey, err := client.GetServerPublicKey()
	if err != nil {
		log.Errorf("failed while getting Management Service public key: %v", err)
		return nil, err
	}

	protoFlow, err := client.GetDeviceAuthorizationFlow(*serverKey)
	if err != nil {
		if s, ok := status.FromError(err); ok && s.Code() == codes.NotFound {
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
func (a *Auth) doMgmLogin(client *mgm.GrpcClient, ctx context.Context, pubSSHKey []byte) (*wgtypes.Key, *mgmProto.LoginResponse, error) {
	serverKey, err := client.GetServerPublicKey()
	if err != nil {
		log.Errorf("failed while getting Management Service public key: %v", err)
		return nil, nil, err
	}

	sysInfo := system.GetInfo(ctx)
	a.setSystemInfoFlags(sysInfo)
	loginResp, err := client.Login(*serverKey, sysInfo, pubSSHKey, a.config.DNSLabels)
	return serverKey, loginResp, err
}

// registerPeer checks whether setupKey was provided via cmd line and if not then it prompts user to enter a key.
// Otherwise tries to register with the provided setupKey via command line.
func (a *Auth) registerPeer(client *mgm.GrpcClient, ctx context.Context, setupKey string, jwtToken string, pubSSHKey []byte) (*mgmProto.LoginResponse, error) {
	serverPublicKey, err := client.GetServerPublicKey()
	if err != nil {
		log.Errorf("failed while getting Management Service public key: %v", err)
		return nil, err
	}

	validSetupKey, err := uuid.Parse(setupKey)
	if err != nil && jwtToken == "" {
		return nil, status.Errorf(codes.InvalidArgument, "invalid setup-key or no sso information provided, err: %v", err)
	}

	log.Debugf("sending peer registration request to Management Service")
	info := system.GetInfo(ctx)
	a.setSystemInfoFlags(info)
	loginResp, err := client.Register(*serverPublicKey, validSetupKey.String(), jwtToken, info, pubSSHKey, a.config.DNSLabels)
	if err != nil {
		log.Errorf("failed registering peer %v", err)
		return nil, err
	}

	log.Infof("peer has been successfully registered on Management Service")

	return loginResp, nil
}

// setSystemInfoFlags sets all configuration flags on the provided system info
func (a *Auth) setSystemInfoFlags(info *system.Info) {
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
}

// reconnect closes the current connection and creates a new one
// It checks if the brokenClient is still the current client before reconnecting
// to avoid multiple threads reconnecting unnecessarily
func (a *Auth) reconnect(ctx context.Context, brokenClient *mgm.GrpcClient) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	// Double-check: if client has already been replaced by another thread, skip reconnection
	if a.client != brokenClient {
		log.Debugf("client already reconnected by another thread, skipping")
		return nil
	}

	// Create new connection FIRST, before closing the old one
	// This ensures a.client is never nil, preventing panics in other threads
	log.Debugf("reconnecting to Management Service %s", a.mgmURL.String())
	mgmClient, err := mgm.NewClient(ctx, a.mgmURL.Host, a.privateKey, a.mgmTLSEnabled)
	if err != nil {
		log.Errorf("failed reconnecting to Management Service %s: %v", a.mgmURL.String(), err)
		// Keep the old client if reconnection fails
		return err
	}

	// Close old connection AFTER new one is successfully created
	oldClient := a.client
	a.client = mgmClient

	if oldClient != nil {
		if err := oldClient.Close(); err != nil {
			log.Debugf("error closing old connection: %v", err)
		}
	}

	log.Debugf("successfully reconnected to Management service %s", a.mgmURL.String())
	return nil
}

// isConnectionError checks if the error is a connection-related error that should trigger reconnection
func isConnectionError(err error) bool {
	if err == nil {
		return false
	}
	s, ok := status.FromError(err)
	if !ok {
		return false
	}
	// These error codes indicate connection issues
	return s.Code() == codes.Unavailable ||
		s.Code() == codes.DeadlineExceeded ||
		s.Code() == codes.Canceled ||
		s.Code() == codes.Internal
}

// withRetry wraps an operation with exponential backoff retry logic
// It automatically reconnects on connection errors
func (a *Auth) withRetry(ctx context.Context, operation func(client *mgm.GrpcClient) error) error {
	backoffSettings := &backoff.ExponentialBackOff{
		InitialInterval:     500 * time.Millisecond,
		RandomizationFactor: 0.5,
		Multiplier:          1.5,
		MaxInterval:         10 * time.Second,
		MaxElapsedTime:      2 * time.Minute,
		Stop:                backoff.Stop,
		Clock:               backoff.SystemClock,
	}
	backoffSettings.Reset()

	return backoff.RetryNotify(
		func() error {
			// Capture the client BEFORE the operation to ensure we track the correct client
			a.mutex.RLock()
			currentClient := a.client
			a.mutex.RUnlock()

			if currentClient == nil {
				return status.Errorf(codes.Unavailable, "client is not initialized")
			}

			// Execute operation with the captured client
			err := operation(currentClient)
			if err == nil {
				return nil
			}

			// If it's a connection error, attempt reconnection using the client that was actually used
			if isConnectionError(err) {
				log.Warnf("connection error detected, attempting reconnection: %v", err)

				if reconnectErr := a.reconnect(ctx, currentClient); reconnectErr != nil {
					log.Errorf("reconnection failed: %v", reconnectErr)
					return reconnectErr
				}
				// Return the original error to trigger retry with the new connection
				return err
			}

			// For authentication errors, don't retry
			if isAuthenticationError(err) {
				return backoff.Permanent(err)
			}

			return err
		},
		backoff.WithContext(backoffSettings, ctx),
		func(err error, duration time.Duration) {
			log.Warnf("operation failed, retrying in %v: %v", duration, err)
		},
	)
}

// isAuthenticationError checks if the error is an authentication-related error that should not be retried.
// Returns true if the error is InvalidArgument or PermissionDenied, indicating that retrying won't help.
func isAuthenticationError(err error) bool {
	if err == nil {
		return false
	}
	s, ok := status.FromError(err)
	if !ok {
		return false
	}
	return s.Code() == codes.InvalidArgument || s.Code() == codes.PermissionDenied
}

// isPermissionDenied checks if the error is a PermissionDenied error.
// This is used to determine if early exit from backoff is needed (e.g., when the server responded but denied access).
func isPermissionDenied(err error) bool {
	if err == nil {
		return false
	}
	s, ok := status.FromError(err)
	if !ok {
		return false
	}
	return s.Code() == codes.PermissionDenied
}

func isLoginNeeded(err error) bool {
	return isAuthenticationError(err)
}

func isRegistrationNeeded(err error) bool {
	return isPermissionDenied(err)
}
