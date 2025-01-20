package types

import (
	"crypto/sha256"
	b64 "encoding/base64"
	"hash/fnv"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/netbirdio/netbird/management/server/util"
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
	// SetupKeyUnlimitedUsage indicates an unlimited usage of a setup key
	SetupKeyUnlimitedUsage = 0
)

// SetupKeyType is the type of setup key
type SetupKeyType string

// SetupKey represents a pre-authorized key used to register machines (peers)
type SetupKey struct {
	Id string
	// AccountID is a reference to Account that this object belongs
	AccountID string `json:"-" gorm:"index"`
	Key       string
	KeySecret string
	Name      string
	Type      SetupKeyType
	CreatedAt time.Time
	ExpiresAt *time.Time
	UpdatedAt time.Time `gorm:"autoUpdateTime:false"`
	// Revoked indicates whether the key was revoked or not (we don't remove them for tracking purposes)
	Revoked bool
	// UsedTimes indicates how many times the key was used
	UsedTimes int
	// LastUsed last time the key was used for peer registration
	LastUsed *time.Time
	// AutoGroups is a list of Group IDs that are auto assigned to a Peer when it uses this key to register
	AutoGroups []string `gorm:"serializer:json"`
	// UsageLimit indicates the number of times this key can be used to enroll a machine.
	// The value of 0 indicates the unlimited usage.
	UsageLimit int
	// Ephemeral indicate if the peers will be ephemeral or not
	Ephemeral bool
}

// Copy copies SetupKey to a new object
func (key *SetupKey) Copy() *SetupKey {
	autoGroups := make([]string, len(key.AutoGroups))
	copy(autoGroups, key.AutoGroups)
	if key.UpdatedAt.IsZero() {
		key.UpdatedAt = key.CreatedAt
	}
	return &SetupKey{
		Id:         key.Id,
		AccountID:  key.AccountID,
		Key:        key.Key,
		KeySecret:  key.KeySecret,
		Name:       key.Name,
		Type:       key.Type,
		CreatedAt:  key.CreatedAt,
		ExpiresAt:  key.ExpiresAt,
		UpdatedAt:  key.UpdatedAt,
		Revoked:    key.Revoked,
		UsedTimes:  key.UsedTimes,
		LastUsed:   key.LastUsed,
		AutoGroups: autoGroups,
		UsageLimit: key.UsageLimit,
		Ephemeral:  key.Ephemeral,
	}
}

// EventMeta returns activity event meta related to the setup key
func (key *SetupKey) EventMeta() map[string]any {
	return map[string]any{"name": key.Name, "type": key.Type, "key": key.KeySecret}
}

// GetLastUsed returns the last used time of the setup key.
func (key *SetupKey) GetLastUsed() time.Time {
	if key.LastUsed != nil {
		return *key.LastUsed
	}
	return time.Time{}
}

// GetExpiresAt returns the expiration time of the setup key.
func (key *SetupKey) GetExpiresAt() time.Time {
	if key.ExpiresAt != nil {
		return *key.ExpiresAt
	}
	return time.Time{}
}

// HiddenKey returns the Key value hidden with "*" and a 5 character prefix.
// E.g., "831F6*******************************"
func HiddenKey(key string, length int) string {
	prefix := key[0:5]
	if length > utf8.RuneCountInString(key) {
		length = utf8.RuneCountInString(key) - len(prefix)
	}
	return prefix + strings.Repeat("*", length)
}

// IncrementUsage makes a copy of a key, increments the UsedTimes by 1 and sets LastUsed to now
func (key *SetupKey) IncrementUsage() *SetupKey {
	c := key.Copy()
	c.UsedTimes++
	c.LastUsed = util.ToPtr(time.Now().UTC())
	return c
}

// IsValid is true if the key was not revoked, is not expired and used not more than it was supposed to
func (key *SetupKey) IsValid() bool {
	return !key.IsRevoked() && !key.IsExpired() && !key.IsOverUsed()
}

// IsRevoked if key was revoked
func (key *SetupKey) IsRevoked() bool {
	return key.Revoked
}

// IsExpired if key was expired
func (key *SetupKey) IsExpired() bool {
	if key.GetExpiresAt().IsZero() {
		return false
	}
	return time.Now().After(key.GetExpiresAt())
}

// IsOverUsed if the key was used too many times. SetupKey.UsageLimit == 0 indicates the unlimited usage.
func (key *SetupKey) IsOverUsed() bool {
	limit := key.UsageLimit
	if key.Type == SetupKeyOneOff {
		limit = 1
	}
	return limit > 0 && key.UsedTimes >= limit
}

// GenerateSetupKey generates a new setup key
func GenerateSetupKey(name string, t SetupKeyType, validFor time.Duration, autoGroups []string,
	usageLimit int, ephemeral bool) (*SetupKey, string) {
	key := strings.ToUpper(uuid.New().String())
	limit := usageLimit
	if t == SetupKeyOneOff {
		limit = 1
	}

	var expiresAt *time.Time
	if validFor != 0 {
		expiresAt = util.ToPtr(time.Now().UTC().Add(validFor))
	}

	hashedKey := sha256.Sum256([]byte(key))
	encodedHashedKey := b64.StdEncoding.EncodeToString(hashedKey[:])

	return &SetupKey{
		Id:         strconv.Itoa(int(Hash(key))),
		Key:        encodedHashedKey,
		KeySecret:  HiddenKey(key, 4),
		Name:       name,
		Type:       t,
		CreatedAt:  time.Now().UTC(),
		ExpiresAt:  expiresAt,
		UpdatedAt:  time.Now().UTC(),
		Revoked:    false,
		UsedTimes:  0,
		AutoGroups: autoGroups,
		UsageLimit: limit,
		Ephemeral:  ephemeral,
	}, key
}

// GenerateDefaultSetupKey generates a default reusable setup key with an unlimited usage and 30 days expiration
func GenerateDefaultSetupKey() (*SetupKey, string) {
	return GenerateSetupKey(DefaultSetupKeyName, SetupKeyReusable, DefaultSetupKeyDuration, []string{},
		SetupKeyUnlimitedUsage, false)
}

func Hash(s string) uint32 {
	h := fnv.New32a()
	_, err := h.Write([]byte(s))
	if err != nil {
		panic(err)
	}
	return h.Sum32()
}
