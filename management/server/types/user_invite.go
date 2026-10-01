package types

import (
	"crypto/sha256"
	b64 "encoding/base64"
	"fmt"
	"hash/crc32"
	"strings"
	"time"

	b "github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/rs/xid"

	"github.com/netbirdio/netbird/base62"
	"github.com/netbirdio/netbird/util/crypt"
)

const (
	// InviteTokenPrefix is the prefix for invite tokens
	InviteTokenPrefix = "nbi_"
	// InviteTokenSecretLength is the length of the random secret part
	InviteTokenSecretLength = 30
	// InviteTokenChecksumLength is the length of the encoded checksum
	InviteTokenChecksumLength = 6
	// InviteTokenLength is the total length of the token (4 + 30 + 6 = 40)
	InviteTokenLength = 40
	// DefaultInviteExpirationSeconds is the default expiration time for invites (72 hours)
	DefaultInviteExpirationSeconds = 259200
	// MinInviteExpirationSeconds is the minimum expiration time for invites (1 hour)
	MinInviteExpirationSeconds = 3600
)

// UserInviteRecord represents an invitation for a user to set up their account (database model)
type UserInviteRecord struct {
	ID          string    `gorm:"primaryKey"`
	AccountID   string    `gorm:"index;not null"`
	Email       string    `gorm:"index;not null"`
	Name        string    `gorm:"not null"`
	Role        string    `gorm:"not null"`
	AutoGroups  []string  `gorm:"serializer:json"`
	HashedToken string    `gorm:"index;not null"` // SHA-256 hash of the token (base64 encoded)
	ExpiresAt   time.Time `gorm:"not null"`
	CreatedAt   time.Time `gorm:"not null"`
	CreatedBy   string    `gorm:"not null"`
}

// TableName returns the table name for GORM
func (UserInviteRecord) TableName() string {
	return "user_invites"
}

// GenerateInviteToken creates a new invite token with the format: nbi_<secret><checksum>
// Returns the hashed token (for storage) and the plain token (to give to the user)
func GenerateInviteToken() (hashedToken string, plainToken string, err error) {
	secret, err := b.Random(InviteTokenSecretLength)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate random secret: %w", err)
	}

	checksum := crc32.ChecksumIEEE([]byte(secret))
	encodedChecksum := base62.Encode(checksum)
	// Left-pad with '0' to ensure exactly 6 characters (fmt.Sprintf %s pads with spaces which breaks base62.Decode)
	paddedChecksum := encodedChecksum
	if len(paddedChecksum) < InviteTokenChecksumLength {
		paddedChecksum = strings.Repeat("0", InviteTokenChecksumLength-len(paddedChecksum)) + paddedChecksum
	}

	plainToken = InviteTokenPrefix + secret + paddedChecksum
	hash := sha256.Sum256([]byte(plainToken))
	hashedToken = b64.StdEncoding.EncodeToString(hash[:])

	return hashedToken, plainToken, nil
}

// HashInviteToken creates a SHA-256 hash of the token (base64 encoded)
func HashInviteToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return b64.StdEncoding.EncodeToString(hash[:])
}

// ValidateInviteToken validates the token format and checksum.
// Returns an error if the token is invalid.
func ValidateInviteToken(token string) error {
	if len(token) != InviteTokenLength {
		return fmt.Errorf("invalid token length")
	}

	prefix := token[:len(InviteTokenPrefix)]
	if prefix != InviteTokenPrefix {
		return fmt.Errorf("invalid token prefix")
	}

	secret := token[len(InviteTokenPrefix) : len(InviteTokenPrefix)+InviteTokenSecretLength]
	encodedChecksum := token[len(InviteTokenPrefix)+InviteTokenSecretLength:]

	verificationChecksum, err := base62.Decode(encodedChecksum)
	if err != nil {
		return fmt.Errorf("checksum decoding failed: %w", err)
	}

	secretChecksum := crc32.ChecksumIEEE([]byte(secret))
	if secretChecksum != verificationChecksum {
		return fmt.Errorf("checksum does not match")
	}

	return nil
}

// IsExpired checks if the invite has expired
func (i *UserInviteRecord) IsExpired() bool {
	return time.Now().After(i.ExpiresAt)
}

// UserInvite contains the result of creating or regenerating an invite
type UserInvite struct {
	UserInfo        *UserInfo
	InviteToken     string
	InviteExpiresAt time.Time
	InviteCreatedAt time.Time
}

// UserInviteInfo contains public information about an invite (for unauthenticated endpoint)
type UserInviteInfo struct {
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	ExpiresAt time.Time `json:"expires_at"`
	Valid     bool      `json:"valid"`
	InvitedBy string    `json:"invited_by"`
}

// NewInviteID generates a new invite ID using xid
func NewInviteID() string {
	return xid.New().String()
}

// EncryptSensitiveData encrypts the invite's sensitive fields (Email and Name) in place.
func (i *UserInviteRecord) EncryptSensitiveData(enc *crypt.FieldEncrypt) error {
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
func (i *UserInviteRecord) DecryptSensitiveData(enc *crypt.FieldEncrypt) error {
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

// Copy creates a deep copy of the UserInviteRecord
func (i *UserInviteRecord) Copy() *UserInviteRecord {
	autoGroups := make([]string, len(i.AutoGroups))
	copy(autoGroups, i.AutoGroups)

	return &UserInviteRecord{
		ID:          i.ID,
		AccountID:   i.AccountID,
		Email:       i.Email,
		Name:        i.Name,
		Role:        i.Role,
		AutoGroups:  autoGroups,
		HashedToken: i.HashedToken,
		ExpiresAt:   i.ExpiresAt,
		CreatedAt:   i.CreatedAt,
		CreatedBy:   i.CreatedBy,
	}
}
