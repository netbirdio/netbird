package oidcprovider

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"gorm.io/gorm"
)

// ErrInvalidRefreshToken is returned when a token is not a valid refresh token
var ErrInvalidRefreshToken = errors.New("invalid refresh token")

// OIDCStorage implements op.Storage interface for the OIDC provider
type OIDCStorage struct {
	store    *Store
	issuer   string
	loginURL func(string) string
}

// NewOIDCStorage creates a new OIDCStorage
func NewOIDCStorage(store *Store, issuer string) *OIDCStorage {
	return &OIDCStorage{
		store:  store,
		issuer: issuer,
	}
}

// SetLoginURL sets the login URL generator function
func (s *OIDCStorage) SetLoginURL(fn func(string) string) {
	s.loginURL = fn
}

// Health checks if the storage is healthy
func (s *OIDCStorage) Health(ctx context.Context) error {
	sqlDB, err := s.store.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.PingContext(ctx)
}

// CreateAuthRequest creates and stores a new authorization request
func (s *OIDCStorage) CreateAuthRequest(ctx context.Context, authReq *oidc.AuthRequest, userID string) (op.AuthRequest, error) {
	req := &AuthRequest{
		ID:            uuid.New().String(),
		ClientID:      authReq.ClientID,
		Scopes:        ToJSONArray(authReq.Scopes),
		RedirectURI:   authReq.RedirectURI,
		State:         authReq.State,
		Nonce:         authReq.Nonce,
		ResponseType:  string(authReq.ResponseType),
		ResponseMode:  string(authReq.ResponseMode),
		CodeChallenge: authReq.CodeChallenge,
		CodeMethod:    string(authReq.CodeChallengeMethod),
		UserID:        userID,
		Done:          userID != "",
		CreatedAt:     time.Now(),
		Prompt:        spaceSeparated(authReq.Prompt),
		UILocales:     authReq.UILocales.String(),
		LoginHint:     authReq.LoginHint,
		ACRValues:     spaceSeparated(authReq.ACRValues),
	}

	if authReq.MaxAge != nil {
		req.MaxAge = int64(*authReq.MaxAge)
	}

	if userID != "" {
		req.AuthTime = time.Now()
	}

	if err := s.store.SaveAuthRequest(ctx, req); err != nil {
		return nil, err
	}

	return &OIDCAuthRequest{req: req, storage: s}, nil
}

// AuthRequestByID retrieves an authorization request by ID
func (s *OIDCStorage) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	req, err := s.store.GetAuthRequestByID(ctx, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("auth request not found: %s", id)
		}
		return nil, err
	}
	return &OIDCAuthRequest{req: req, storage: s}, nil
}

// AuthRequestByCode retrieves an authorization request by code
func (s *OIDCStorage) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	authCode, err := s.store.GetAuthCodeByCode(ctx, code)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("auth code not found: %s", code)
		}
		return nil, err
	}

	if time.Now().After(authCode.ExpiresAt) {
		_ = s.store.DeleteAuthCode(ctx, code)
		return nil, errors.New("auth code expired")
	}

	req, err := s.store.GetAuthRequestByID(ctx, authCode.AuthRequestID)
	if err != nil {
		return nil, err
	}

	return &OIDCAuthRequest{req: req, storage: s}, nil
}

// SaveAuthCode saves an authorization code linked to an auth request
func (s *OIDCStorage) SaveAuthCode(ctx context.Context, id, code string) error {
	authCode := &AuthCode{
		Code:          code,
		AuthRequestID: id,
		ExpiresAt:     time.Now().Add(10 * time.Minute),
	}
	return s.store.SaveAuthCode(ctx, authCode)
}

// DeleteAuthRequest deletes an authorization request
func (s *OIDCStorage) DeleteAuthRequest(ctx context.Context, id string) error {
	return s.store.DeleteAuthRequest(ctx, id)
}

// CreateAccessToken creates and stores an access token
func (s *OIDCStorage) CreateAccessToken(ctx context.Context, request op.TokenRequest) (string, time.Time, error) {
	tokenID := uuid.New().String()
	expiration := time.Now().Add(5 * time.Minute)

	// Get client ID from the request if possible
	var clientID string
	if authReq, ok := request.(op.AuthRequest); ok {
		clientID = authReq.GetClientID()
	} else if refreshReq, ok := request.(op.RefreshTokenRequest); ok {
		clientID = refreshReq.GetClientID()
	}

	token := &AccessToken{
		ID:            tokenID,
		ApplicationID: clientID,
		Subject:       request.GetSubject(),
		Audience:      ToJSONArray(request.GetAudience()),
		Scopes:        ToJSONArray(request.GetScopes()),
		Expiration:    expiration,
	}

	if err := s.store.SaveAccessToken(ctx, token); err != nil {
		return "", time.Time{}, err
	}

	return tokenID, expiration, nil
}

// CreateAccessAndRefreshTokens creates both access and refresh tokens
func (s *OIDCStorage) CreateAccessAndRefreshTokens(ctx context.Context, request op.TokenRequest, currentRefreshToken string) (accessTokenID string, newRefreshToken string, expiration time.Time, err error) {
	// Delete old refresh token if provided
	if currentRefreshToken != "" {
		_ = s.store.DeleteRefreshTokenByToken(ctx, currentRefreshToken)
	}

	// Create access token
	accessTokenID, expiration, err = s.CreateAccessToken(ctx, request)
	if err != nil {
		return "", "", time.Time{}, err
	}

	// Get additional info from the request if possible
	var clientID string
	var authTime time.Time
	var amr []string

	if authReq, ok := request.(op.AuthRequest); ok {
		clientID = authReq.GetClientID()
		authTime = authReq.GetAuthTime()
		amr = authReq.GetAMR()
	} else if refreshReq, ok := request.(op.RefreshTokenRequest); ok {
		clientID = refreshReq.GetClientID()
		authTime = refreshReq.GetAuthTime()
		amr = refreshReq.GetAMR()
	}

	// Create refresh token
	refreshToken := &RefreshToken{
		ID:            uuid.New().String(),
		Token:         uuid.New().String(),
		ApplicationID: clientID,
		Subject:       request.GetSubject(),
		Audience:      ToJSONArray(request.GetAudience()),
		Scopes:        ToJSONArray(request.GetScopes()),
		AuthTime:      authTime,
		AMR:           ToJSONArray(amr),
		Expiration:    time.Now().Add(5 * time.Hour), // 5 hour refresh token lifetime
	}

	if authReq, ok := request.(op.AuthRequest); ok {
		refreshToken.AuthRequestID = authReq.GetID()
	}

	if err := s.store.SaveRefreshToken(ctx, refreshToken); err != nil {
		return "", "", time.Time{}, err
	}

	return accessTokenID, refreshToken.Token, expiration, nil
}

// TokenRequestByRefreshToken retrieves token request info from refresh token
func (s *OIDCStorage) TokenRequestByRefreshToken(ctx context.Context, refreshToken string) (op.RefreshTokenRequest, error) {
	token, err := s.store.GetRefreshToken(ctx, refreshToken)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("refresh token not found")
		}
		return nil, err
	}

	if time.Now().After(token.Expiration) {
		_ = s.store.DeleteRefreshTokenByToken(ctx, refreshToken)
		return nil, errors.New("refresh token expired")
	}

	return &OIDCRefreshToken{token: token}, nil
}

// TerminateSession terminates a user session
func (s *OIDCStorage) TerminateSession(ctx context.Context, userID, clientID string) error {
	// For now, we don't track sessions separately
	return nil
}

// RevokeToken revokes a token
func (s *OIDCStorage) RevokeToken(ctx context.Context, tokenOrID string, userID string, clientID string) *oidc.Error {
	// Try to delete as refresh token
	if err := s.store.DeleteRefreshTokenByToken(ctx, tokenOrID); err == nil {
		return nil
	}

	// Try to delete as access token
	if err := s.store.DeleteAccessToken(ctx, tokenOrID); err == nil {
		return nil
	}

	return nil // Silently succeed even if token not found (per spec)
}

// GetRefreshTokenInfo returns info about a refresh token
func (s *OIDCStorage) GetRefreshTokenInfo(ctx context.Context, clientID string, token string) (userID string, tokenID string, err error) {
	refreshToken, err := s.store.GetRefreshToken(ctx, token)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", "", ErrInvalidRefreshToken
		}
		return "", "", err
	}

	if refreshToken.ApplicationID != clientID {
		return "", "", ErrInvalidRefreshToken
	}

	return refreshToken.Subject, refreshToken.ID, nil
}

// GetClientByClientID retrieves a client by ID
func (s *OIDCStorage) GetClientByClientID(ctx context.Context, clientID string) (op.Client, error) {
	client, err := s.store.GetClientByID(ctx, clientID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("client not found: %s", clientID)
		}
		return nil, err
	}
	return NewOIDCClient(client, s.loginURL), nil
}

// AuthorizeClientIDSecret validates client credentials
func (s *OIDCStorage) AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error {
	_, err := s.store.ValidateClientSecret(ctx, clientID, clientSecret)
	return err
}

// SetUserinfoFromScopes sets userinfo claims based on scopes
func (s *OIDCStorage) SetUserinfoFromScopes(ctx context.Context, userinfo *oidc.UserInfo, userID, clientID string, scopes []string) error {
	return s.setUserinfo(ctx, userinfo, userID, scopes)
}

// SetUserinfoFromToken sets userinfo claims from an access token
func (s *OIDCStorage) SetUserinfoFromToken(ctx context.Context, userinfo *oidc.UserInfo, tokenID, subject, origin string) error {
	token, err := s.store.GetAccessTokenByID(ctx, tokenID)
	if err != nil {
		return err
	}
	return s.setUserinfo(ctx, userinfo, token.Subject, ParseJSONArray(token.Scopes))
}

// setUserinfo populates userinfo based on user data and scopes
func (s *OIDCStorage) setUserinfo(ctx context.Context, userinfo *oidc.UserInfo, userID string, scopes []string) error {
	user, err := s.store.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}

	for _, scope := range scopes {
		switch scope {
		case oidc.ScopeOpenID:
			userinfo.Subject = user.ID
		case oidc.ScopeProfile:
			userinfo.Name = fmt.Sprintf("%s %s", user.FirstName, user.LastName)
			userinfo.GivenName = user.FirstName
			userinfo.FamilyName = user.LastName
			userinfo.PreferredUsername = user.Username
			userinfo.Locale = oidc.NewLocale(user.GetPreferredLanguage())
		case oidc.ScopeEmail:
			userinfo.Email = user.Email
			userinfo.EmailVerified = oidc.Bool(user.EmailVerified)
		case oidc.ScopePhone:
			userinfo.PhoneNumber = user.Phone
			userinfo.PhoneNumberVerified = user.PhoneVerified
		}
	}

	return nil
}

// SetIntrospectionFromToken sets introspection response from token
func (s *OIDCStorage) SetIntrospectionFromToken(ctx context.Context, introspection *oidc.IntrospectionResponse, tokenID, subject, clientID string) error {
	token, err := s.store.GetAccessTokenByID(ctx, tokenID)
	if err != nil {
		return err
	}

	introspection.Active = true
	introspection.Subject = token.Subject
	introspection.ClientID = token.ApplicationID
	introspection.Scope = ParseJSONArray(token.Scopes)
	introspection.Expiration = oidc.FromTime(token.Expiration)
	introspection.IssuedAt = oidc.FromTime(token.CreatedAt)
	introspection.Audience = ParseJSONArray(token.Audience)
	introspection.Issuer = s.issuer

	return nil
}

// GetPrivateClaimsFromScopes returns additional claims based on scopes
func (s *OIDCStorage) GetPrivateClaimsFromScopes(ctx context.Context, userID, clientID string, scopes []string) (map[string]any, error) {
	return nil, nil
}

// GetKeyByIDAndClientID retrieves a key by ID for a client
func (s *OIDCStorage) GetKeyByIDAndClientID(ctx context.Context, keyID, clientID string) (*jose.JSONWebKey, error) {
	return nil, errors.New("not implemented")
}

// ValidateJWTProfileScopes validates scopes for JWT profile grant
func (s *OIDCStorage) ValidateJWTProfileScopes(ctx context.Context, userID string, scopes []string) ([]string, error) {
	return scopes, nil
}

// SigningKey returns the active signing key for token signing
func (s *OIDCStorage) SigningKey(ctx context.Context) (op.SigningKey, error) {
	key, err := s.store.GetSigningKey(ctx)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(key.PrivateKey)
	if block == nil {
		return nil, errors.New("failed to decode private key PEM")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return &signingKey{
		id:         key.ID,
		algorithm:  jose.RS256,
		privateKey: privateKey,
	}, nil
}

// SignatureAlgorithms returns supported signature algorithms
func (s *OIDCStorage) SignatureAlgorithms(ctx context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{jose.RS256}, nil
}

// KeySet returns the public key set for token verification
func (s *OIDCStorage) KeySet(ctx context.Context) ([]op.Key, error) {
	key, err := s.store.GetSigningKey(ctx)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(key.PublicKey)
	if block == nil {
		return nil, errors.New("failed to decode public key PEM")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not RSA")
	}

	return []op.Key{
		&publicKeyInfo{
			id:        key.ID,
			algorithm: jose.RS256,
			publicKey: rsaKey,
		},
	}, nil
}

// Device Authorization Flow methods

// StoreDeviceAuthorization stores a device authorization request
func (s *OIDCStorage) StoreDeviceAuthorization(ctx context.Context, clientID, deviceCode, userCode string, expires time.Time, scopes []string) error {
	auth := &DeviceAuth{
		DeviceCode: deviceCode,
		UserCode:   userCode,
		ClientID:   clientID,
		Scopes:     ToJSONArray(scopes),
		Expiration: expires,
	}
	return s.store.SaveDeviceAuth(ctx, auth)
}

// GetDeviceAuthorizationState retrieves the state of a device authorization
func (s *OIDCStorage) GetDeviceAuthorizationState(ctx context.Context, clientID, deviceCode string) (*op.DeviceAuthorizationState, error) {
	auth, err := s.store.GetDeviceAuthByDeviceCode(ctx, deviceCode)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("device authorization not found")
		}
		return nil, err
	}

	if auth.ClientID != clientID {
		return nil, errors.New("client ID mismatch")
	}

	if time.Now().After(auth.Expiration) {
		_ = s.store.DeleteDeviceAuth(ctx, deviceCode)
		return &op.DeviceAuthorizationState{Expires: auth.Expiration}, nil
	}

	state := &op.DeviceAuthorizationState{
		ClientID: auth.ClientID,
		Scopes:   ParseJSONArray(auth.Scopes),
		Expires:  auth.Expiration,
	}

	if auth.Denied {
		state.Denied = true
	} else if auth.Done {
		state.Done = true
		state.Subject = auth.Subject
	}

	return state, nil
}

// GetDeviceAuthorizationByUserCode retrieves device auth by user code
func (s *OIDCStorage) GetDeviceAuthorizationByUserCode(ctx context.Context, userCode string) (*op.DeviceAuthorizationState, error) {
	auth, err := s.store.GetDeviceAuthByUserCode(ctx, userCode)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("device authorization not found")
		}
		return nil, err
	}

	if time.Now().After(auth.Expiration) {
		return nil, errors.New("device authorization expired")
	}

	return &op.DeviceAuthorizationState{
		ClientID: auth.ClientID,
		Scopes:   ParseJSONArray(auth.Scopes),
		Expires:  auth.Expiration,
		Done:     auth.Done,
		Denied:   auth.Denied,
		Subject:  auth.Subject,
	}, nil
}

// CompleteDeviceAuthorization marks a device authorization as complete
func (s *OIDCStorage) CompleteDeviceAuthorization(ctx context.Context, userCode, subject string) error {
	auth, err := s.store.GetDeviceAuthByUserCode(ctx, userCode)
	if err != nil {
		return err
	}

	auth.Done = true
	auth.Subject = subject
	return s.store.UpdateDeviceAuth(ctx, auth)
}

// DenyDeviceAuthorization marks a device authorization as denied
func (s *OIDCStorage) DenyDeviceAuthorization(ctx context.Context, userCode string) error {
	auth, err := s.store.GetDeviceAuthByUserCode(ctx, userCode)
	if err != nil {
		return err
	}

	auth.Denied = true
	return s.store.UpdateDeviceAuth(ctx, auth)
}

// User authentication methods

// CheckUsernamePassword validates user credentials
func (s *OIDCStorage) CheckUsernamePassword(username, password, authRequestID string) error {
	ctx := context.Background()

	_, err := s.store.ValidateUserPassword(ctx, username, password)
	if err != nil {
		return err
	}

	return nil
}

// CheckUsernamePasswordSimple validates user credentials and returns the user ID
func (s *OIDCStorage) CheckUsernamePasswordSimple(username, password string) (string, error) {
	ctx := context.Background()

	user, err := s.store.ValidateUserPassword(ctx, username, password)
	if err != nil {
		return "", err
	}

	return user.ID, nil
}

// CompleteAuthRequest completes an auth request after user authentication
func (s *OIDCStorage) CompleteAuthRequest(ctx context.Context, authRequestID, userID string) error {
	req, err := s.store.GetAuthRequestByID(ctx, authRequestID)
	if err != nil {
		return err
	}

	req.UserID = userID
	req.Done = true
	req.AuthTime = time.Now()

	return s.store.UpdateAuthRequest(ctx, req)
}

// Helper types

// signingKey implements op.SigningKey
type signingKey struct {
	id         string
	algorithm  jose.SignatureAlgorithm
	privateKey *rsa.PrivateKey
}

func (k *signingKey) SignatureAlgorithm() jose.SignatureAlgorithm {
	return k.algorithm
}

func (k *signingKey) Key() interface{} {
	return k.privateKey
}

func (k *signingKey) ID() string {
	return k.id
}

// publicKeyInfo implements op.Key
type publicKeyInfo struct {
	id        string
	algorithm jose.SignatureAlgorithm
	publicKey *rsa.PublicKey
}

func (k *publicKeyInfo) ID() string {
	return k.id
}

func (k *publicKeyInfo) Algorithm() jose.SignatureAlgorithm {
	return k.algorithm
}

func (k *publicKeyInfo) Use() string {
	return "sig"
}

func (k *publicKeyInfo) Key() interface{} {
	return k.publicKey
}

// OIDCAuthRequest wraps AuthRequest for the op.AuthRequest interface
type OIDCAuthRequest struct {
	req     *AuthRequest
	storage *OIDCStorage
}

func (r *OIDCAuthRequest) GetID() string          { return r.req.ID }
func (r *OIDCAuthRequest) GetACR() string         { return "" }
func (r *OIDCAuthRequest) GetAMR() []string       { return []string{"pwd"} }
func (r *OIDCAuthRequest) GetAudience() []string  { return []string{r.req.ClientID} }
func (r *OIDCAuthRequest) GetAuthTime() time.Time { return r.req.AuthTime }
func (r *OIDCAuthRequest) GetClientID() string    { return r.req.ClientID }
func (r *OIDCAuthRequest) GetCodeChallenge() *oidc.CodeChallenge {
	if r.req.CodeChallenge == "" {
		return nil
	}
	return &oidc.CodeChallenge{
		Challenge: r.req.CodeChallenge,
		Method:    oidc.CodeChallengeMethod(r.req.CodeMethod),
	}
}
func (r *OIDCAuthRequest) GetNonce() string       { return r.req.Nonce }
func (r *OIDCAuthRequest) GetRedirectURI() string { return r.req.RedirectURI }
func (r *OIDCAuthRequest) GetResponseType() oidc.ResponseType {
	return oidc.ResponseType(r.req.ResponseType)
}
func (r *OIDCAuthRequest) GetResponseMode() oidc.ResponseMode {
	return oidc.ResponseMode(r.req.ResponseMode)
}
func (r *OIDCAuthRequest) GetScopes() []string { return ParseJSONArray(r.req.Scopes) }
func (r *OIDCAuthRequest) GetState() string    { return r.req.State }
func (r *OIDCAuthRequest) GetSubject() string  { return r.req.UserID }
func (r *OIDCAuthRequest) Done() bool          { return r.req.Done }

// OIDCRefreshToken wraps RefreshToken for the op.RefreshTokenRequest interface
type OIDCRefreshToken struct {
	token *RefreshToken
}

func (r *OIDCRefreshToken) GetAMR() []string                 { return ParseJSONArray(r.token.AMR) }
func (r *OIDCRefreshToken) GetAudience() []string            { return ParseJSONArray(r.token.Audience) }
func (r *OIDCRefreshToken) GetAuthTime() time.Time           { return r.token.AuthTime }
func (r *OIDCRefreshToken) GetClientID() string              { return r.token.ApplicationID }
func (r *OIDCRefreshToken) GetScopes() []string              { return ParseJSONArray(r.token.Scopes) }
func (r *OIDCRefreshToken) GetSubject() string               { return r.token.Subject }
func (r *OIDCRefreshToken) SetCurrentScopes(scopes []string) {}

// Helper functions

func spaceSeparated(items []string) string {
	return strings.Join(items, " ")
}
