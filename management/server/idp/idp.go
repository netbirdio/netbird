package idp

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/netbirdio/netbird/management/server/telemetry"
)

const (
	// UnsetAccountID is a special key to map users without an account ID
	UnsetAccountID = "unset"
)

// Manager idp manager interface
type Manager interface {
	UpdateUserAppMetadata(userId string, appMetadata AppMetadata) error
	GetUserDataByID(userId string, appMetadata AppMetadata) (*UserData, error)
	GetAccount(accountId string) ([]*UserData, error)
	GetAllAccounts() (map[string][]*UserData, error)
	CreateUser(email, name, accountID, invitedByEmail string) (*UserData, error)
	GetUserByEmail(email string) ([]*UserData, error)
	InviteUserByID(userID string) error
	DeleteUser(userID string) error
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
	ManagerType               string
	ClientConfig              *ClientConfig
	ExtraConfig               ExtraConfig
	Auth0ClientCredentials    *Auth0ClientConfig
	AzureClientCredentials    *AzureClientConfig
	KeycloakClientCredentials *KeycloakClientConfig
	ZitadelClientCredentials  *ZitadelClientConfig
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
	WTPendingInvite *bool  `json:"wt_pending_invite,omitempty"`
	WTInvitedBy     string `json:"wt_invited_by_email,omitempty"`
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
	if config.ClientConfig != nil {
		config.ClientConfig.Issuer = strings.TrimSuffix(config.ClientConfig.Issuer, "/")
	}

	switch strings.ToLower(config.ManagerType) {
	case "none", "":
		return nil, nil //nolint:nilnil
	case "auth0":
		auth0ClientConfig := config.Auth0ClientCredentials
		if config.ClientConfig != nil {
			auth0ClientConfig = &Auth0ClientConfig{
				Audience:     config.ExtraConfig["Audience"],
				AuthIssuer:   config.ClientConfig.Issuer,
				ClientID:     config.ClientConfig.ClientID,
				ClientSecret: config.ClientConfig.ClientSecret,
				GrantType:    config.ClientConfig.GrantType,
			}
		}

		return NewAuth0Manager(*auth0ClientConfig, appMetrics)
	case "azure":
		azureClientConfig := config.AzureClientCredentials
		if config.ClientConfig != nil {
			azureClientConfig = &AzureClientConfig{
				ClientID:         config.ClientConfig.ClientID,
				ClientSecret:     config.ClientConfig.ClientSecret,
				GrantType:        config.ClientConfig.GrantType,
				TokenEndpoint:    config.ClientConfig.TokenEndpoint,
				ObjectID:         config.ExtraConfig["ObjectId"],
				GraphAPIEndpoint: config.ExtraConfig["GraphApiEndpoint"],
			}
		}

		return NewAzureManager(*azureClientConfig, appMetrics)
	case "keycloak":
		keycloakClientConfig := config.KeycloakClientCredentials
		if config.ClientConfig != nil {
			keycloakClientConfig = &KeycloakClientConfig{
				ClientID:      config.ClientConfig.ClientID,
				ClientSecret:  config.ClientConfig.ClientSecret,
				GrantType:     config.ClientConfig.GrantType,
				TokenEndpoint: config.ClientConfig.TokenEndpoint,
				AdminEndpoint: config.ExtraConfig["AdminEndpoint"],
			}
		}

		return NewKeycloakManager(*keycloakClientConfig, appMetrics)
	case "zitadel":
		zitadelClientConfig := config.ZitadelClientCredentials
		if config.ClientConfig != nil {
			zitadelClientConfig = &ZitadelClientConfig{
				ClientID:           config.ClientConfig.ClientID,
				ClientSecret:       config.ClientConfig.ClientSecret,
				GrantType:          config.ClientConfig.GrantType,
				TokenEndpoint:      config.ClientConfig.TokenEndpoint,
				ManagementEndpoint: config.ExtraConfig["ManagementEndpoint"],
			}
		}

		return NewZitadelManager(*zitadelClientConfig, appMetrics)
	case "authentik":
		authentikConfig := AuthentikClientConfig{
			Issuer:        config.ClientConfig.Issuer,
			ClientID:      config.ClientConfig.ClientID,
			TokenEndpoint: config.ClientConfig.TokenEndpoint,
			GrantType:     config.ClientConfig.GrantType,
			Username:      config.ExtraConfig["Username"],
			Password:      config.ExtraConfig["Password"],
		}
		return NewAuthentikManager(authentikConfig, appMetrics)
	case "okta":
		oktaClientConfig := OktaClientConfig{
			Issuer:        config.ClientConfig.Issuer,
			TokenEndpoint: config.ClientConfig.TokenEndpoint,
			GrantType:     config.ClientConfig.GrantType,
			APIToken:      config.ExtraConfig["ApiToken"],
		}
		return NewOktaManager(oktaClientConfig, appMetrics)
	case "google":
		googleClientConfig := GoogleWorkspaceClientConfig{
			ServiceAccountKey: config.ExtraConfig["ServiceAccountKey"],
			CustomerID:        config.ExtraConfig["CustomerId"],
		}
		return NewGoogleWorkspaceManager(googleClientConfig, appMetrics)
	case "jumpcloud":
		jumpcloudConfig := JumpCloudClientConfig{
			APIToken: config.ExtraConfig["ApiToken"],
		}
		return NewJumpCloudManager(jumpcloudConfig, appMetrics)
	default:
		return nil, fmt.Errorf("invalid manager type: %s", config.ManagerType)
	}
}
