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

// DeviceAuthorizationFlow represents Device Authorization Flow information
type DeviceAuthorizationFlow struct {
	Provider       string
	ProviderConfig DeviceAuthProviderConfig
}

// DeviceAuthProviderConfig has all attributes needed to initiate a device authorization flow
type DeviceAuthProviderConfig struct {
	// ClientID An IDP application client id
	ClientID string
	// ClientSecret An IDP application client secret
	ClientSecret string
	// Domain An IDP API domain
	// Deprecated. Use OIDCConfigEndpoint instead
	Domain string
	// Audience An Audience for to authorization validation
	Audience string
	// TokenEndpoint is the endpoint of an IDP manager where clients can obtain access token
	TokenEndpoint string
	// DeviceAuthEndpoint is the endpoint of an IDP manager where clients can obtain device authorization code
	DeviceAuthEndpoint string
	// Scopes provides the scopes to be included in the token request
	Scope string
	// UseIDToken indicates if the id token should be used for authentication
	UseIDToken bool
}

// GetDeviceAuthorizationFlowInfo initialize a DeviceAuthorizationFlow instance and return with it
func GetDeviceAuthorizationFlowInfo(ctx context.Context, privateKey string, mgmURL *url.URL) (DeviceAuthorizationFlow, error) {
	// validate our peer's Wireguard PRIVATE key
	myPrivateKey, err := wgtypes.ParseKey(privateKey)
	if err != nil {
		log.Errorf("failed parsing Wireguard key %s: [%s]", privateKey, err.Error())
		return DeviceAuthorizationFlow{}, err
	}

	var mgmTLSEnabled bool
	if mgmURL.Scheme == "https" {
		mgmTLSEnabled = true
	}

	log.Debugf("connecting to Management Service %s", mgmURL.String())
	mgmClient, err := mgm.NewClient(ctx, mgmURL.Host, myPrivateKey, mgmTLSEnabled)
	if err != nil {
		log.Errorf("failed connecting to Management Service %s %v", mgmURL.String(), err)
		return DeviceAuthorizationFlow{}, err
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
		return DeviceAuthorizationFlow{}, err
	}

	protoDeviceAuthorizationFlow, err := mgmClient.GetDeviceAuthorizationFlow(*serverKey)
	if err != nil {
		if s, ok := status.FromError(err); ok && s.Code() == codes.NotFound {
			log.Warnf("server couldn't find device flow, contact admin: %v", err)
			return DeviceAuthorizationFlow{}, err
		}
		log.Errorf("failed to retrieve device flow: %v", err)
		return DeviceAuthorizationFlow{}, err
	}

	deviceAuthorizationFlow := DeviceAuthorizationFlow{
		Provider: protoDeviceAuthorizationFlow.Provider.String(),

		ProviderConfig: DeviceAuthProviderConfig{
			Audience:           protoDeviceAuthorizationFlow.GetProviderConfig().GetAudience(),
			ClientID:           protoDeviceAuthorizationFlow.GetProviderConfig().GetClientID(),
			ClientSecret:       protoDeviceAuthorizationFlow.GetProviderConfig().GetClientSecret(),
			Domain:             protoDeviceAuthorizationFlow.GetProviderConfig().Domain,
			TokenEndpoint:      protoDeviceAuthorizationFlow.GetProviderConfig().GetTokenEndpoint(),
			DeviceAuthEndpoint: protoDeviceAuthorizationFlow.GetProviderConfig().GetDeviceAuthEndpoint(),
			Scope:              protoDeviceAuthorizationFlow.GetProviderConfig().GetScope(),
			UseIDToken:         protoDeviceAuthorizationFlow.GetProviderConfig().GetUseIDToken(),
		},
	}

	// keep compatibility with older management versions
	if deviceAuthorizationFlow.ProviderConfig.Scope == "" {
		deviceAuthorizationFlow.ProviderConfig.Scope = "openid"
	}

	err = isDeviceAuthProviderConfigValid(deviceAuthorizationFlow.ProviderConfig)
	if err != nil {
		return DeviceAuthorizationFlow{}, err
	}

	return deviceAuthorizationFlow, nil
}

func isDeviceAuthProviderConfigValid(config DeviceAuthProviderConfig) error {
	errorMSGFormat := "invalid provider configuration received from management: %s value is empty. Contact your NetBird administrator"
	if config.Audience == "" {
		return fmt.Errorf(errorMSGFormat, "Audience")
	}
	if config.ClientID == "" {
		return fmt.Errorf(errorMSGFormat, "Client ID")
	}
	if config.TokenEndpoint == "" {
		return fmt.Errorf(errorMSGFormat, "Token Endpoint")
	}
	if config.DeviceAuthEndpoint == "" {
		return fmt.Errorf(errorMSGFormat, "Device Auth Endpoint")
	}
	if config.Scope == "" {
		return fmt.Errorf(errorMSGFormat, "Device Auth Scopes")
	}
	return nil
}
