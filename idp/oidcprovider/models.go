package oidcprovider

import (
	"time"

	"golang.org/x/text/language"
)

// User represents an OIDC user stored in the database
type User struct {
	ID                string `gorm:"primaryKey"`
	Username          string `gorm:"uniqueIndex;not null"`
	Password          string `gorm:"not null"` // bcrypt hashed
	Email             string
	EmailVerified     bool
	FirstName         string
	LastName          string
	Phone             string
	PhoneVerified     bool
	PreferredLanguage string // language tag string
	IsAdmin           bool
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// GetPreferredLanguage returns the user's preferred language as a language.Tag
func (u *User) GetPreferredLanguage() language.Tag {
	if u.PreferredLanguage == "" {
		return language.English
	}
	tag, err := language.Parse(u.PreferredLanguage)
	if err != nil {
		return language.English
	}
	return tag
}

// Client represents an OIDC client (application) stored in the database
type Client struct {
	ID              string `gorm:"primaryKey"`
	Secret          string // bcrypt hashed, empty for public clients
	Name            string
	RedirectURIs    string // JSON array of redirect URIs
	PostLogoutURIs  string // JSON array of post-logout redirect URIs
	ApplicationType string // native, web, user_agent
	AuthMethod      string // none, client_secret_basic, client_secret_post, private_key_jwt
	ResponseTypes   string // JSON array: code, id_token, token
	GrantTypes      string // JSON array: authorization_code, refresh_token, client_credentials, urn:ietf:params:oauth:grant-type:device_code
	AccessTokenType string // bearer or jwt
	DevMode         bool   // allows non-HTTPS redirect URIs
	IDTokenLifetime int64  // in seconds, default 3600 (1 hour)
	ClockSkew       int64  // in seconds, allowed clock skew
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// AuthRequest represents an ongoing authorization request
type AuthRequest struct {
	ID            string `gorm:"primaryKey"`
	ClientID      string `gorm:"index"`
	Scopes        string // JSON array of scopes
	RedirectURI   string
	State         string
	Nonce         string
	ResponseType  string
	ResponseMode  string
	CodeChallenge string
	CodeMethod    string // S256 or plain
	UserID        string // set after user authentication
	Done          bool   // true when user has authenticated
	AuthTime      time.Time
	CreatedAt     time.Time
	MaxAge        int64  // max authentication age in seconds
	Prompt        string // none, login, consent, select_account
	UILocales     string // space-separated list of locales
	LoginHint     string
	ACRValues     string // space-separated list of ACR values
}

// AuthCode represents an authorization code
type AuthCode struct {
	Code          string `gorm:"primaryKey"`
	AuthRequestID string `gorm:"index"`
	CreatedAt     time.Time
	ExpiresAt     time.Time
}

// AccessToken represents an access token
type AccessToken struct {
	ID            string `gorm:"primaryKey"`
	ApplicationID string `gorm:"index"`
	Subject       string `gorm:"index"`
	Audience      string // JSON array
	Scopes        string // JSON array
	Expiration    time.Time
	CreatedAt     time.Time
}

// RefreshToken represents a refresh token
type RefreshToken struct {
	ID            string `gorm:"primaryKey"`
	Token         string `gorm:"uniqueIndex"`
	AuthRequestID string
	ApplicationID string `gorm:"index"`
	Subject       string `gorm:"index"`
	Audience      string // JSON array
	Scopes        string // JSON array
	AMR           string // JSON array of authentication methods
	AuthTime      time.Time
	Expiration    time.Time
	CreatedAt     time.Time
}

// DeviceAuth represents a device authorization request
type DeviceAuth struct {
	DeviceCode string `gorm:"primaryKey"`
	UserCode   string `gorm:"uniqueIndex"`
	ClientID   string `gorm:"index"`
	Scopes     string // JSON array
	Subject    string // set after user authentication
	Audience   string // JSON array
	Done       bool   // true when user has authorized
	Denied     bool   // true when user has denied
	Expiration time.Time
	CreatedAt  time.Time
}

// SigningKey represents a signing key for JWTs
type SigningKey struct {
	ID         string `gorm:"primaryKey"`
	Algorithm  string // RS256
	PrivateKey []byte // PEM encoded
	PublicKey  []byte // PEM encoded
	CreatedAt  time.Time
	Active     bool
}
