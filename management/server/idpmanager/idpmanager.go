package idpmanager

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

type IDPManager interface {
	UpdateUserAppMetadata(userId string, appMetadata AppMetadata) error
}

type ManagerConfig struct {
	ManagerType            string
	Auth0ClientCredentials Auth0ClientConfig
}

type ManagerCredentials interface {
	Authenticate() (JWTToken, error)
}

// ManagerHTTPClient http client interface for API calls
type ManagerHTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type ManagerHelper interface {
	Marshal(v interface{}) ([]byte, error)
	Unmarshal(data []byte, v interface{}) error
}

type AppMetadata struct {
	// Wiretrustee account id to update in the IDP
	// maps to wt_account_id when json.marshal
	WTAccountId string `json:"wt_account_id"`
}

type JWTToken struct {
	AccessToken   string `json:"access_token"`
	ExpiresIn     int    `json:"expires_in"`
	expiresInTime time.Time
	Scope         string `json:"scope"`
	TokenType     string `json:"token_type"`
}

func NewManager(config ManagerConfig) (IDPManager, error) {
	switch strings.ToLower(config.ManagerType) {
	case "none", "":
		return nil, nil
	case "auth0":
		return NewDefaultAuth0Manager(config.Auth0ClientCredentials), nil
	default:
		return nil, fmt.Errorf("invalid manager type: %s", config.ManagerType)
	}
}
