package oidcprovider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Store handles persistence for OIDC provider data
type Store struct {
	db *gorm.DB
	mu sync.RWMutex
}

// NewStore creates a new Store with SQLite backend
func NewStore(ctx context.Context, dataDir string) (*Store, error) {
	dbPath := fmt.Sprintf("%s/oidc.db", dataDir)

	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open OIDC database: %w", err)
	}

	// Enable WAL mode for better concurrency
	if err := db.Exec("PRAGMA journal_mode=WAL").Error; err != nil {
		log.WithContext(ctx).Warnf("failed to enable WAL mode: %v", err)
	}

	// Auto-migrate tables
	if err := db.AutoMigrate(
		&User{},
		&Client{},
		&AuthRequest{},
		&AuthCode{},
		&AccessToken{},
		&RefreshToken{},
		&DeviceAuth{},
		&SigningKey{},
	); err != nil {
		return nil, fmt.Errorf("failed to migrate OIDC database: %w", err)
	}

	store := &Store{db: db}

	// Ensure we have a signing key
	if err := store.ensureSigningKey(ctx); err != nil {
		return nil, fmt.Errorf("failed to ensure signing key: %w", err)
	}

	return store, nil
}

// Close closes the database connection
func (s *Store) Close() error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// ensureSigningKey creates a signing key if one doesn't exist
func (s *Store) ensureSigningKey(ctx context.Context) error {
	var key SigningKey
	err := s.db.WithContext(ctx).Where("active = ?", true).First(&key).Error
	if err == nil {
		return nil // Key exists
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}

	// Generate new RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %w", err)
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	newKey := &SigningKey{
		ID:         uuid.New().String(),
		Algorithm:  "RS256",
		PrivateKey: privateKeyPEM,
		PublicKey:  publicKeyPEM,
		CreatedAt:  time.Now(),
		Active:     true,
	}

	return s.db.WithContext(ctx).Create(newKey).Error
}

// GetSigningKey returns the active signing key
func (s *Store) GetSigningKey(ctx context.Context) (*SigningKey, error) {
	var key SigningKey
	err := s.db.WithContext(ctx).Where("active = ?", true).First(&key).Error
	if err != nil {
		return nil, err
	}
	return &key, nil
}

// User operations

// CreateUser creates a new user with bcrypt hashed password
func (s *Store) CreateUser(ctx context.Context, user *User) error {
	if user.ID == "" {
		user.ID = uuid.New().String()
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}
	user.Password = string(hashedPassword)
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()

	return s.db.WithContext(ctx).Create(user).Error
}

// GetUserByID retrieves a user by ID
func (s *Store) GetUserByID(ctx context.Context, id string) (*User, error) {
	var user User
	err := s.db.WithContext(ctx).Where("id = ?", id).First(&user).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// GetUserByUsername retrieves a user by username
func (s *Store) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	var user User
	err := s.db.WithContext(ctx).Where("username = ?", username).First(&user).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// ValidateUserPassword validates a user's password
func (s *Store) ValidateUserPassword(ctx context.Context, username, password string) (*User, error) {
	user, err := s.GetUserByUsername(ctx, username)
	if err != nil {
		return nil, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, errors.New("invalid password")
	}

	return user, nil
}

// ListUsers returns all users
func (s *Store) ListUsers(ctx context.Context) ([]*User, error) {
	var users []*User
	err := s.db.WithContext(ctx).Find(&users).Error
	return users, err
}

// UpdateUser updates a user
func (s *Store) UpdateUser(ctx context.Context, user *User) error {
	user.UpdatedAt = time.Now()
	return s.db.WithContext(ctx).Save(user).Error
}

// DeleteUser deletes a user
func (s *Store) DeleteUser(ctx context.Context, id string) error {
	return s.db.WithContext(ctx).Delete(&User{}, "id = ?", id).Error
}

// UpdateUserPassword updates a user's password
func (s *Store) UpdateUserPassword(ctx context.Context, id, password string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	return s.db.WithContext(ctx).Model(&User{}).Where("id = ?", id).Updates(map[string]interface{}{
		"password":   string(hashedPassword),
		"updated_at": time.Now(),
	}).Error
}

// Client operations

// CreateClient creates a new OIDC client
func (s *Store) CreateClient(ctx context.Context, client *Client) error {
	if client.ID == "" {
		client.ID = uuid.New().String()
	}

	// Hash secret if provided
	if client.Secret != "" {
		hashedSecret, err := bcrypt.GenerateFromPassword([]byte(client.Secret), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("failed to hash client secret: %w", err)
		}
		client.Secret = string(hashedSecret)
	}

	client.CreatedAt = time.Now()
	client.UpdatedAt = time.Now()

	return s.db.WithContext(ctx).Create(client).Error
}

// GetClientByID retrieves a client by ID
func (s *Store) GetClientByID(ctx context.Context, id string) (*Client, error) {
	var client Client
	err := s.db.WithContext(ctx).Where("id = ?", id).First(&client).Error
	if err != nil {
		return nil, err
	}
	return &client, nil
}

// ValidateClientSecret validates a client's secret
func (s *Store) ValidateClientSecret(ctx context.Context, clientID, secret string) (*Client, error) {
	client, err := s.GetClientByID(ctx, clientID)
	if err != nil {
		return nil, err
	}

	// Public clients have no secret
	if client.Secret == "" && secret == "" {
		return client, nil
	}

	if err := bcrypt.CompareHashAndPassword([]byte(client.Secret), []byte(secret)); err != nil {
		return nil, errors.New("invalid client secret")
	}

	return client, nil
}

// ListClients returns all clients
func (s *Store) ListClients(ctx context.Context) ([]*Client, error) {
	var clients []*Client
	err := s.db.WithContext(ctx).Find(&clients).Error
	return clients, err
}

// DeleteClient deletes a client
func (s *Store) DeleteClient(ctx context.Context, id string) error {
	return s.db.WithContext(ctx).Delete(&Client{}, "id = ?", id).Error
}

// AuthRequest operations

// SaveAuthRequest saves an authorization request
func (s *Store) SaveAuthRequest(ctx context.Context, req *AuthRequest) error {
	if req.ID == "" {
		req.ID = uuid.New().String()
	}
	req.CreatedAt = time.Now()
	return s.db.WithContext(ctx).Create(req).Error
}

// GetAuthRequestByID retrieves an auth request by ID
func (s *Store) GetAuthRequestByID(ctx context.Context, id string) (*AuthRequest, error) {
	var req AuthRequest
	err := s.db.WithContext(ctx).Where("id = ?", id).First(&req).Error
	if err != nil {
		return nil, err
	}
	return &req, nil
}

// UpdateAuthRequest updates an auth request
func (s *Store) UpdateAuthRequest(ctx context.Context, req *AuthRequest) error {
	return s.db.WithContext(ctx).Save(req).Error
}

// DeleteAuthRequest deletes an auth request
func (s *Store) DeleteAuthRequest(ctx context.Context, id string) error {
	return s.db.WithContext(ctx).Delete(&AuthRequest{}, "id = ?", id).Error
}

// AuthCode operations

// SaveAuthCode saves an authorization code
func (s *Store) SaveAuthCode(ctx context.Context, code *AuthCode) error {
	code.CreatedAt = time.Now()
	if code.ExpiresAt.IsZero() {
		code.ExpiresAt = time.Now().Add(10 * time.Minute) // 10 minute expiry
	}
	return s.db.WithContext(ctx).Create(code).Error
}

// GetAuthCodeByCode retrieves an auth code
func (s *Store) GetAuthCodeByCode(ctx context.Context, code string) (*AuthCode, error) {
	var authCode AuthCode
	err := s.db.WithContext(ctx).Where("code = ?", code).First(&authCode).Error
	if err != nil {
		return nil, err
	}
	return &authCode, nil
}

// DeleteAuthCode deletes an auth code
func (s *Store) DeleteAuthCode(ctx context.Context, code string) error {
	return s.db.WithContext(ctx).Delete(&AuthCode{}, "code = ?", code).Error
}

// Token operations

// SaveAccessToken saves an access token
func (s *Store) SaveAccessToken(ctx context.Context, token *AccessToken) error {
	if token.ID == "" {
		token.ID = uuid.New().String()
	}
	token.CreatedAt = time.Now()
	return s.db.WithContext(ctx).Create(token).Error
}

// GetAccessTokenByID retrieves an access token
func (s *Store) GetAccessTokenByID(ctx context.Context, id string) (*AccessToken, error) {
	var token AccessToken
	err := s.db.WithContext(ctx).Where("id = ?", id).First(&token).Error
	if err != nil {
		return nil, err
	}
	return &token, nil
}

// DeleteAccessToken deletes an access token
func (s *Store) DeleteAccessToken(ctx context.Context, id string) error {
	return s.db.WithContext(ctx).Delete(&AccessToken{}, "id = ?", id).Error
}

// RefreshToken operations

// SaveRefreshToken saves a refresh token
func (s *Store) SaveRefreshToken(ctx context.Context, token *RefreshToken) error {
	if token.ID == "" {
		token.ID = uuid.New().String()
	}
	if token.Token == "" {
		token.Token = uuid.New().String()
	}
	token.CreatedAt = time.Now()
	return s.db.WithContext(ctx).Create(token).Error
}

// GetRefreshToken retrieves a refresh token by token value
func (s *Store) GetRefreshToken(ctx context.Context, token string) (*RefreshToken, error) {
	var rt RefreshToken
	err := s.db.WithContext(ctx).Where("token = ?", token).First(&rt).Error
	if err != nil {
		return nil, err
	}
	return &rt, nil
}

// DeleteRefreshToken deletes a refresh token
func (s *Store) DeleteRefreshToken(ctx context.Context, id string) error {
	return s.db.WithContext(ctx).Delete(&RefreshToken{}, "id = ?", id).Error
}

// DeleteRefreshTokenByToken deletes a refresh token by token value
func (s *Store) DeleteRefreshTokenByToken(ctx context.Context, token string) error {
	return s.db.WithContext(ctx).Delete(&RefreshToken{}, "token = ?", token).Error
}

// DeviceAuth operations

// SaveDeviceAuth saves a device authorization
func (s *Store) SaveDeviceAuth(ctx context.Context, auth *DeviceAuth) error {
	auth.CreatedAt = time.Now()
	return s.db.WithContext(ctx).Create(auth).Error
}

// GetDeviceAuthByDeviceCode retrieves device auth by device code
func (s *Store) GetDeviceAuthByDeviceCode(ctx context.Context, deviceCode string) (*DeviceAuth, error) {
	var auth DeviceAuth
	err := s.db.WithContext(ctx).Where("device_code = ?", deviceCode).First(&auth).Error
	if err != nil {
		return nil, err
	}
	return &auth, nil
}

// GetDeviceAuthByUserCode retrieves device auth by user code
func (s *Store) GetDeviceAuthByUserCode(ctx context.Context, userCode string) (*DeviceAuth, error) {
	var auth DeviceAuth
	err := s.db.WithContext(ctx).Where("user_code = ?", userCode).First(&auth).Error
	if err != nil {
		return nil, err
	}
	return &auth, nil
}

// UpdateDeviceAuth updates a device authorization
func (s *Store) UpdateDeviceAuth(ctx context.Context, auth *DeviceAuth) error {
	return s.db.WithContext(ctx).Save(auth).Error
}

// DeleteDeviceAuth deletes a device authorization
func (s *Store) DeleteDeviceAuth(ctx context.Context, deviceCode string) error {
	return s.db.WithContext(ctx).Delete(&DeviceAuth{}, "device_code = ?", deviceCode).Error
}

// Cleanup operations

// CleanupExpired removes expired tokens and auth requests
func (s *Store) CleanupExpired(ctx context.Context) error {
	now := time.Now()

	// Delete expired auth codes
	if err := s.db.WithContext(ctx).Delete(&AuthCode{}, "expires_at < ?", now).Error; err != nil {
		return err
	}

	// Delete expired access tokens
	if err := s.db.WithContext(ctx).Delete(&AccessToken{}, "expiration < ?", now).Error; err != nil {
		return err
	}

	// Delete expired refresh tokens
	if err := s.db.WithContext(ctx).Delete(&RefreshToken{}, "expiration < ?", now).Error; err != nil {
		return err
	}

	// Delete expired device authorizations
	if err := s.db.WithContext(ctx).Delete(&DeviceAuth{}, "expiration < ?", now).Error; err != nil {
		return err
	}

	// Delete old auth requests (older than 1 hour)
	oneHourAgo := now.Add(-1 * time.Hour)
	if err := s.db.WithContext(ctx).Delete(&AuthRequest{}, "created_at < ?", oneHourAgo).Error; err != nil {
		return err
	}

	return nil
}

// Helper functions for JSON serialization

// ParseJSONArray parses a JSON array string into a slice
func ParseJSONArray(jsonStr string) []string {
	if jsonStr == "" {
		return nil
	}
	var result []string
	if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
		return nil
	}
	return result
}

// ToJSONArray converts a slice to a JSON array string
func ToJSONArray(arr []string) string {
	if len(arr) == 0 {
		return "[]"
	}
	data, err := json.Marshal(arr)
	if err != nil {
		return "[]"
	}
	return string(data)
}
