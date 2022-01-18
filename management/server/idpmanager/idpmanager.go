package idpmanager

import (
	"fmt"
	"strings"
	"time"
)

type IDPManager interface {
	UpdateUserAppMetadata(userId string, appMetadata AppMetadata) error
}

type ManagerConfig struct {
	ManagerType            string
	Auth0ClientCredentials Auth0ClientCredentials
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
		return NewAuth0Manager(config.Auth0ClientCredentials), nil
	default:
		return nil, fmt.Errorf("invalid manager type: %s", config.ManagerType)
	}
}
