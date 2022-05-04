package idp

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Manager idp manager interface
type Manager interface {
	UpdateUserAppMetadata(userId string, appMetadata AppMetadata) error
	GetUserDataByID(userId string, appMetadata AppMetadata) (*UserData, error)
	GetBatchedUserData(accountId string) ([]*UserData, error)
}

// Config an idp configuration struct to be loaded from management server's config file
type Config struct {
	ManagerType            string
	Auth0ClientCredentials Auth0ClientConfig
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
	Email string `json:"email"`
	Name  string `json:"name"`
	ID    string `json:"user_id"`
}

// AppMetadata user app metadata to associate with a profile
type AppMetadata struct {
	// Wiretrustee account id to update in the IDP
	// maps to wt_account_id when json.marshal
	WTAccountId string `json:"wt_account_id"`
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
func NewManager(config Config) (Manager, error) {
	switch strings.ToLower(config.ManagerType) {
	case "none", "":
		return nil, nil
	case "auth0":
		return NewAuth0Manager(config.Auth0ClientCredentials)
	default:
		return nil, fmt.Errorf("invalid manager type: %s", config.ManagerType)
	}
}
