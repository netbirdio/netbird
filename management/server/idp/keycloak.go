package idp

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/netbirdio/netbird/management/server/telemetry"
)

// KeycloakManager keycloak manager client instance.
type KeycloakManager struct {
	authIssuer  string
	httpClient  ManagerHTTPClient
	credentials ManagerCredentials
	helper      ManagerHelper
	appMetrics  telemetry.AppMetrics
}

// KeycloakClientConfig keycloak manager client configurations.
type KeycloakClientConfig struct {
	Audience      string
	AuthIssuer    string
	ClientID      string
	ClientSecret  string
	TokenEndpoint string
	GrantType     string
}

// KeycloakCredentials keycloak authentication information.
type KeycloakCredentials struct {
	clientConfig KeycloakClientConfig
	helper       ManagerHelper
	httpClient   ManagerHTTPClient
	jwtToken     JWTToken
	mux          sync.Mutex
	appMetrics   telemetry.AppMetrics
}

// NewKeycloakManager creates a new instance of the KeycloakManager.
func NewKeycloakManager(config KeycloakClientConfig, appMetrics telemetry.AppMetrics) (*KeycloakManager, error) {
	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
	httpTransport.MaxIdleConns = 5

	httpClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: httpTransport,
	}

	helper := JsonParser{}

	if config.ClientID == "" || config.ClientSecret == "" || config.GrantType == "" || config.Audience == "" || config.AuthIssuer == "" || config.TokenEndpoint == "" {
		return nil, fmt.Errorf("keycloak idp configuration is not complete")
	}

	if config.GrantType != "client_credentials" {
		return nil, fmt.Errorf("keycloak idp configuration failed. Grant Type should be client_credentials")
	}

	if !strings.HasPrefix(strings.ToLower(config.AuthIssuer), "https://") {
		return nil, fmt.Errorf("keycloak idp configuration failed. AuthIssuer should contain https://")
	}

	credentials := &KeycloakCredentials{
		clientConfig: config,
		httpClient:   httpClient,
		helper:       helper,
		appMetrics:   appMetrics,
	}

	return &KeycloakManager{
		authIssuer:  config.AuthIssuer,
		httpClient:  httpClient,
		credentials: credentials,
		helper:      helper,
		appMetrics:  appMetrics,
	}, nil
}

// Authenticate retrieves access token to use the keycloak Management API.
func (kc *KeycloakCredentials) Authenticate() (JWTToken, error) {
	panic("not implemented")
}

// CreateUser creates a new user in Auth0 Idp and sends an invite.
func (km *KeycloakManager) CreateUser(email string, name string, accountID string) (*UserData, error) {
	panic("not implemented") // TODO: Implement
}

// GetUserByEmail searches users with a given email.
// If no users have been found, this function returns an empty list.
func (km *KeycloakManager) GetUserByEmail(email string) ([]*UserData, error) {
	panic("not implemented") // TODO: Implement
}

// GetUserDataByID requests user data from auth0 via ID.
func (km *KeycloakManager) GetUserDataByID(userId string, appMetadata AppMetadata) (*UserData, error) {
	panic("not implemented") // TODO: Implement
}

// UpdateUserAppMetadata updates user app metadata based on userId and metadata map.
func (km *KeycloakManager) GetAccount(accountId string) ([]*UserData, error) {
	panic("not implemented") // TODO: Implement
}

// GetAllAccounts gets all registered accounts with corresponding user data.
// It returns a list of users indexed by accountID.
func (km *KeycloakManager) GetAllAccounts() (map[string][]*UserData, error) {
	panic("not implemented") // TODO: Implement
}

// UpdateUserAppMetadata updates user app metadata based on userId and metadata map.
func (km *KeycloakManager) UpdateUserAppMetadata(userId string, appMetadata AppMetadata) error {
	panic("not implemented") // TODO: Implement
}
