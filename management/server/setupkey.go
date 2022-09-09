package server

import (
	"github.com/google/uuid"
	"hash/fnv"
	"strconv"
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
	Id        string
	Key       string
	Name      string
	Type      SetupKeyType
	CreatedAt time.Time
	ExpiresAt time.Time
	// Revoked indicates whether the key was revoked or not (we don't remove them for tracking purposes)
	Revoked bool
	// UsedTimes indicates how many times the key was used
	UsedTimes int
	// LastUsed last time the key was used for peer registration
	LastUsed time.Time
	// AutoGroups is a list of Group IDs that are auto assigned to a Peer when it uses this key to register
	AutoGroups []string
}

// Copy copies SetupKey to a new object
func (key *SetupKey) Copy() *SetupKey {
	return &SetupKey{
		Id:         key.Id,
		Key:        key.Key,
		Name:       key.Name,
		Type:       key.Type,
		CreatedAt:  key.CreatedAt,
		ExpiresAt:  key.ExpiresAt,
		Revoked:    key.Revoked,
		UsedTimes:  key.UsedTimes,
		LastUsed:   key.LastUsed,
		AutoGroups: key.AutoGroups,
	}
}

// IncrementUsage makes a copy of a key, increments the UsedTimes by 1 and sets LastUsed to now
func (key *SetupKey) IncrementUsage() *SetupKey {
	c := key.Copy()
	c.UsedTimes = c.UsedTimes + 1
	c.LastUsed = time.Now()
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
	return time.Now().After(key.ExpiresAt)
}

// IsOverUsed if key was used too many times
func (key *SetupKey) IsOverUsed() bool {
	return key.Type == SetupKeyOneOff && key.UsedTimes >= 1
}

// GenerateSetupKey generates a new setup key
func GenerateSetupKey(name string, t SetupKeyType, validFor time.Duration, autoGroups []string) *SetupKey {
	key := strings.ToUpper(uuid.New().String())
	createdAt := time.Now()
	return &SetupKey{
		Id:         strconv.Itoa(int(Hash(key))),
		Key:        key,
		Name:       name,
		Type:       t,
		CreatedAt:  createdAt,
		ExpiresAt:  createdAt.Add(validFor),
		Revoked:    false,
		UsedTimes:  0,
		AutoGroups: autoGroups,
	}
}

// GenerateDefaultSetupKey generates a default setup key
func GenerateDefaultSetupKey() *SetupKey {
	return GenerateSetupKey(DefaultSetupKeyName, SetupKeyReusable, DefaultSetupKeyDuration, []string{})
}

func Hash(s string) uint32 {
	h := fnv.New32a()
	_, err := h.Write([]byte(s))
	if err != nil {
		panic(err)
	}
	return h.Sum32()
}
