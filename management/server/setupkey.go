package server

import (
	"github.com/google/uuid"
	"strings"
	"time"
)

const (
	// SetupKeyReusable is a multi-use key (can be used for multiple machines)
	SetupKeyReusable SetupKeyType = "reusable"
	// SetupKeyOneOff is a single use key (can be used only once)
	SetupKeyOneOff SetupKeyType = "one-off"

	// DefaultSetupKeyDuration = 1 month
	DefaultSetupKeyDuration = 24 * 30 * time.Hour
	// DefaultSetupKeyName is a default name of the default setup key
	DefaultSetupKeyName = "Default key"
)

// SetupKeyType is the type of setup key
type SetupKeyType string

// SetupKey represents a pre-authorized key used to register machines (peers)
type SetupKey struct {
	Key       string
	Name      string
	Type      SetupKeyType
	CreatedAt time.Time
	ExpiresAt time.Time
	// Revoked indicates whether the key was revoked or not (we don't remove them for tracking purposes)
	Revoked bool
	// UsedTimes indicates how many times the key was used
	UsedTimes int
}

// IsValid is true if the key was not revoked, is not expired and used not more than it was supposed to
func (key *SetupKey) IsValid() bool {
	expired := time.Now().After(key.ExpiresAt)
	overUsed := key.Type == SetupKeyOneOff && key.UsedTimes >= 1
	return !key.Revoked && !expired && !overUsed
}

// GenerateSetupKey generates a new setup key
func GenerateSetupKey(name string, t SetupKeyType, validFor time.Duration) *SetupKey {
	createdAt := time.Now()
	return &SetupKey{
		Key:       strings.ToUpper(uuid.New().String()),
		Name:      name,
		Type:      t,
		CreatedAt: createdAt,
		ExpiresAt: createdAt.Add(validFor),
		Revoked:   false,
		UsedTimes: 0,
	}
}

// GenerateDefaultSetupKey generates a default setup key
func GenerateDefaultSetupKey() *SetupKey {
	return GenerateSetupKey(DefaultSetupKeyName, SetupKeyReusable, DefaultSetupKeyDuration)
}
