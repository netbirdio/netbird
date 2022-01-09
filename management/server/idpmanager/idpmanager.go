package idpmanager

import "time"

type IDPManager interface {
	UpdateUserAppMetadata(userId string, appMetadata AppMetadata) error
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
