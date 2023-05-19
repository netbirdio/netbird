package idp

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/netbirdio/netbird/management/server/telemetry"
)

// Manager idp manager interface
type Manager interface {
	UpdateUserAppMetadata(userId string, appMetadata AppMetadata) error
	GetUserDataByID(userId string, appMetadata AppMetadata) (*UserData, error)
	GetAccount(accountId string) ([]*UserData, error)
	GetAllAccounts() (map[string][]*UserData, error)
	CreateUser(email string, name string, accountID string) (*UserData, error)
	GetUserByEmail(email string) ([]*UserData, error)
}

// ClientConfig defines common client configuration for all IdP manager
type ClientConfig struct {
	Issuer        string
	TokenEndpoint string
	ClientID      string
	ClientSecret  string
	GrantType     string
}

// ExtraConfig stores IdP specific config that are unique to individual IdPs
type ExtraConfig map[string]string

// Config an idp configuration struct to be loaded from management server's config file
type Config struct {
	ManagerType  string
	ClientConfig *ClientConfig
	ExtraConfig  ExtraConfig
}

// ManagerCredentials interface that authenticates using the credential of each type of idp
type ManagerCredentials interface {
	Authenticate() (JWTToken, error)
}

// ManagerHTTPClient http client interface for API calls
type ManagerHTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// ManagerHelper helper
type ManagerHelper interface {
	Marshal(v interface{}) ([]byte, error)
	Unmarshal(data []byte, v interface{}) error
}

type UserData struct {
	Email       string      `json:"email"`
	Name        string      `json:"name"`
	ID          string      `json:"user_id"`
	AppMetadata AppMetadata `json:"app_metadata"`
}

// AppMetadata user app metadata to associate with a profile
type AppMetadata struct {
	// WTAccountID is a NetBird (previously Wiretrustee) account id to update in the IDP
	// maps to wt_account_id when json.marshal
	WTAccountID     string `json:"wt_account_id,omitempty"`
	WTPendingInvite *bool  `json:"wt_pending_invite"`
}

// JWTToken a JWT object that holds information of a token
type JWTToken struct {
	AccessToken   string `json:"access_token"`
	ExpiresIn     int    `json:"expires_in"`
	expiresInTime time.Time
	Scope         string `json:"scope"`
	TokenType     string `json:"token_type"`
}

// NewManager returns a new idp manager based on the configuration that it receives
func NewManager(config Config, appMetrics telemetry.AppMetrics) (Manager, error) {
	switch strings.ToLower(config.ManagerType) {
	case "none", "":
		return nil, nil
	case "auth0":
		if config.ClientConfig == nil {
			return nil, fmt.Errorf("IdP client configuration is empty")
		}

		auth0ClientConfig := Auth0ClientConfig{
			Audience:     config.ExtraConfig["Audience"],
			AuthIssuer:   config.ClientConfig.Issuer,
			ClientID:     config.ClientConfig.ClientID,
			ClientSecret: config.ClientConfig.ClientSecret,
			GrantType:    config.ClientConfig.GrantType,
		}
		return NewAuth0Manager(auth0ClientConfig, appMetrics)
	//case "azure":
	//	return NewAzureManager(config.OIDCConfig, config.AzureClientCredentials, appMetrics)
	case "keycloak":
		if config.ClientConfig == nil {
			return nil, fmt.Errorf("IdP client configuration is empty")
		}

		keycloakClientConfig := KeycloakClientConfig{
			ClientID:      config.ClientConfig.ClientID,
			ClientSecret:  config.ClientConfig.ClientSecret,
			GrantType:     config.ClientConfig.GrantType,
			TokenEndpoint: config.ClientConfig.TokenEndpoint,
			AdminEndpoint: config.ExtraConfig["AdminEndpoint"],
		}
		return NewKeycloakManager(keycloakClientConfig, appMetrics)
	case "zitadel":
		if config.ClientConfig == nil {
			return nil, fmt.Errorf("IdP client configuration is empty")
		}

		zitadelClientConfig := ZitadelClientConfig{
			ClientID:           config.ClientConfig.ClientID,
			ClientSecret:       config.ClientConfig.ClientSecret,
			GrantType:          config.ClientConfig.GrantType,
			TokenEndpoint:      config.ClientConfig.TokenEndpoint,
			ManagementEndpoint: config.ExtraConfig["ManagementEndpoint"],
		}
		return NewZitadelManager(zitadelClientConfig, appMetrics)
	default:
		return nil, fmt.Errorf("invalid manager type: %s", config.ManagerType)
	}
}
