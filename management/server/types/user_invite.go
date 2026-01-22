package types

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/rs/xid"

	"github.com/netbirdio/netbird/util/crypt"
)

const (
	// InviteTokenPrefix is the prefix for invite tokens
	InviteTokenPrefix = "nbi_"
	// InviteTokenSecretLength is the length of the random secret part
	InviteTokenSecretLength = 32
	// DefaultInviteExpirationSeconds is the default expiration time for invites (72 hours)
	DefaultInviteExpirationSeconds = 259200
)

// UserInvite represents an invitation for a user to set up their account
type UserInvite struct {
	ID         string    `gorm:"primaryKey"`
	AccountID  string    `gorm:"index;not null"`
	Email      string    `gorm:"index;not null"`
	Name       string    `gorm:"not null"`
	Role       string    `gorm:"not null"`
	AutoGroups []string  `gorm:"serializer:json"`
	TokenHash  string    `gorm:"not null"` // SHA-256 hash of the token
	ExpiresAt  time.Time `gorm:"not null"`
	CreatedAt  time.Time `gorm:"not null"`
	CreatedBy  string    `gorm:"not null"`
}

// TableName returns the table name for GORM
func (UserInvite) TableName() string {
	return "user_invites"
}

// InviteToken represents a parsed invite token
type InviteToken struct {
	InviteID string
	Secret   string
}

// GenerateInviteToken creates a new invite token with the format: nbi_{inviteID}-{secret}
func GenerateInviteToken(inviteID string) (token string, hash string, err error) {
	secret, err := generateRandomString(InviteTokenSecretLength)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate random secret: %w", err)
	}

	token = fmt.Sprintf("%s%s-%s", InviteTokenPrefix, inviteID, secret)
	hash = HashInviteToken(token)

	return token, hash, nil
}

// HashInviteToken creates a SHA-256 hash of the token
func HashInviteToken(token string) string {
	h := sha256.New()
	h.Write([]byte(token))
	return hex.EncodeToString(h.Sum(nil))
}

// ParseInviteToken parses a token string and returns its components
func ParseInviteToken(token string) (*InviteToken, error) {
	if !strings.HasPrefix(token, InviteTokenPrefix) {
		return nil, fmt.Errorf("invalid token format: missing prefix")
	}

	// Remove prefix
	rest := strings.TrimPrefix(token, InviteTokenPrefix)

	// Split by '-' to get inviteID and secret
	parts := strings.SplitN(rest, "-", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid token format: missing separator")
	}

	inviteID := parts[0]
	secret := parts[1]

	if inviteID == "" {
		return nil, fmt.Errorf("invalid token format: empty invite ID")
	}
	if secret == "" {
		return nil, fmt.Errorf("invalid token format: empty secret")
	}

	return &InviteToken{
		InviteID: inviteID,
		Secret:   secret,
	}, nil
}

// VerifyInviteTokenHash verifies that the provided token matches the stored hash
// using constant-time comparison to prevent timing attacks
func VerifyInviteTokenHash(token, storedHash string) bool {
	computedHash := HashInviteToken(token)
	return subtle.ConstantTimeCompare([]byte(computedHash), []byte(storedHash)) == 1
}

// IsExpired checks if the invite has expired
func (i *UserInvite) IsExpired() bool {
	return time.Now().After(i.ExpiresAt)
}

// UserInviteResponse contains the result of creating or regenerating an invite
type UserInviteResponse struct {
	UserInfo        *UserInfo
	InviteLink      string
	InviteExpiresAt time.Time
}

// UserInviteInfo contains public information about an invite (for unauthenticated endpoint)
type UserInviteInfo struct {
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	ExpiresAt time.Time `json:"expires_at"`
	Valid     bool      `json:"valid"`
}

// NewInviteID generates a new invite ID using xid
func NewInviteID() string {
	return xid.New().String()
}

// EncryptSensitiveData encrypts the invite's sensitive fields (Email and Name) in place.
func (i *UserInvite) EncryptSensitiveData(enc *crypt.FieldEncrypt) error {
	if enc == nil {
		return nil
	}

	var err error
	if i.Email != "" {
		i.Email, err = enc.Encrypt(i.Email)
		if err != nil {
			return fmt.Errorf("encrypt email: %w", err)
		}
	}

	if i.Name != "" {
		i.Name, err = enc.Encrypt(i.Name)
		if err != nil {
			return fmt.Errorf("encrypt name: %w", err)
		}
	}

	return nil
}

// DecryptSensitiveData decrypts the invite's sensitive fields (Email and Name) in place.
func (i *UserInvite) DecryptSensitiveData(enc *crypt.FieldEncrypt) error {
	if enc == nil {
		return nil
	}

	var err error
	if i.Email != "" {
		i.Email, err = enc.Decrypt(i.Email)
		if err != nil {
			return fmt.Errorf("decrypt email: %w", err)
		}
	}

	if i.Name != "" {
		i.Name, err = enc.Decrypt(i.Name)
		if err != nil {
			return fmt.Errorf("decrypt name: %w", err)
		}
	}

	return nil
}

// Copy creates a deep copy of the UserInvite
func (i *UserInvite) Copy() *UserInvite {
	autoGroups := make([]string, len(i.AutoGroups))
	copy(autoGroups, i.AutoGroups)

	return &UserInvite{
		ID:         i.ID,
		AccountID:  i.AccountID,
		Email:      i.Email,
		Name:       i.Name,
		Role:       i.Role,
		AutoGroups: autoGroups,
		TokenHash:  i.TokenHash,
		ExpiresAt:  i.ExpiresAt,
		CreatedAt:  i.CreatedAt,
		CreatedBy:  i.CreatedBy,
	}
}

// generateRandomString generates a cryptographically secure random string
func generateRandomString(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b), nil
}
