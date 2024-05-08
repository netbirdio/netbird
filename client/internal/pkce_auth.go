package internal

import (
	"context"
	"fmt"
	"net/url"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	mgm "github.com/netbirdio/netbird/management/client"
)

// PKCEAuthorizationFlow represents PKCE Authorization Flow information
type PKCEAuthorizationFlow struct {
	ProviderConfig PKCEAuthProviderConfig
}

// PKCEAuthProviderConfig has all attributes needed to initiate pkce authorization flow
type PKCEAuthProviderConfig struct {
	// ClientID An IDP application client id
	ClientID string
	// ClientSecret An IDP application client secret
	ClientSecret string
	// Audience An Audience for to authorization validation
	Audience string
	// TokenEndpoint is the endpoint of an IDP manager where clients can obtain access token
	TokenEndpoint string
	// AuthorizationEndpoint is the endpoint of an IDP manager where clients can obtain authorization code
	AuthorizationEndpoint string
	// Scopes provides the scopes to be included in the token request
	Scope string
	// RedirectURL handles authorization code from IDP manager
	RedirectURLs []string
	// UseIDToken indicates if the id token should be used for authentication
	UseIDToken bool
}

// GetPKCEAuthorizationFlowInfo initialize a PKCEAuthorizationFlow instance and return with it
func GetPKCEAuthorizationFlowInfo(ctx context.Context, privateKey string, mgmURL *url.URL) (PKCEAuthorizationFlow, error) {
	// validate our peer's Wireguard PRIVATE key
	myPrivateKey, err := wgtypes.ParseKey(privateKey)
	if err != nil {
		log.Errorf("failed parsing Wireguard key %s: [%s]", privateKey, err.Error())
		return PKCEAuthorizationFlow{}, err
	}

	var mgmTLSEnabled bool
	if mgmURL.Scheme == "https" {
		mgmTLSEnabled = true
	}

	log.Debugf("connecting to Management Service %s", mgmURL.String())
	mgmClient, err := mgm.NewClient(ctx, mgmURL.Host, myPrivateKey, mgmTLSEnabled)
	if err != nil {
		log.Errorf("failed connecting to Management Service %s %v", mgmURL.String(), err)
		return PKCEAuthorizationFlow{}, err
	}
	log.Debugf("connected to the Management service %s", mgmURL.String())

	defer func() {
		err = mgmClient.Close()
		if err != nil {
			log.Warnf("failed to close the Management service client %v", err)
		}
	}()

	serverKey, err := mgmClient.GetServerPublicKey()
	if err != nil {
		log.Errorf("failed while getting Management Service public key: %v", err)
		return PKCEAuthorizationFlow{}, err
	}

	protoPKCEAuthorizationFlow, err := mgmClient.GetPKCEAuthorizationFlow(*serverKey)
	if err != nil {
		if s, ok := status.FromError(err); ok && s.Code() == codes.NotFound {
			log.Warnf("server couldn't find pkce flow, contact admin: %v", err)
			return PKCEAuthorizationFlow{}, err
		}
		log.Errorf("failed to retrieve pkce flow: %v", err)
		return PKCEAuthorizationFlow{}, err
	}

	authFlow := PKCEAuthorizationFlow{
		ProviderConfig: PKCEAuthProviderConfig{
			Audience:              protoPKCEAuthorizationFlow.GetProviderConfig().GetAudience(),
			ClientID:              protoPKCEAuthorizationFlow.GetProviderConfig().GetClientID(),
			ClientSecret:          protoPKCEAuthorizationFlow.GetProviderConfig().GetClientSecret(),
			TokenEndpoint:         protoPKCEAuthorizationFlow.GetProviderConfig().GetTokenEndpoint(),
			AuthorizationEndpoint: protoPKCEAuthorizationFlow.GetProviderConfig().GetAuthorizationEndpoint(),
			Scope:                 protoPKCEAuthorizationFlow.GetProviderConfig().GetScope(),
			RedirectURLs:          protoPKCEAuthorizationFlow.GetProviderConfig().GetRedirectURLs(),
			UseIDToken:            protoPKCEAuthorizationFlow.GetProviderConfig().GetUseIDToken(),
		},
	}

	err = isPKCEProviderConfigValid(authFlow.ProviderConfig)
	if err != nil {
		return PKCEAuthorizationFlow{}, err
	}

	return authFlow, nil
}

func isPKCEProviderConfigValid(config PKCEAuthProviderConfig) error {
	errorMSGFormat := "invalid provider configuration received from management: %s value is empty. Contact your NetBird administrator"
	if config.ClientID == "" {
		return fmt.Errorf(errorMSGFormat, "Client ID")
	}
	if config.TokenEndpoint == "" {
		return fmt.Errorf(errorMSGFormat, "Token Endpoint")
	}
	if config.AuthorizationEndpoint == "" {
		return fmt.Errorf(errorMSGFormat, "Authorization Auth Endpoint")
	}
	if config.Scope == "" {
		return fmt.Errorf(errorMSGFormat, "PKCE Auth Scopes")
	}
	if config.RedirectURLs == nil {
		return fmt.Errorf(errorMSGFormat, "PKCE Redirect URLs")
	}
	return nil
}
