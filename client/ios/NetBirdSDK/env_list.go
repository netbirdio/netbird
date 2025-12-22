//go:build ios

package NetBirdSDK

import "github.com/netbirdio/netbird/client/internal/peer"

// EnvList is an exported struct to be bound by gomobile
type EnvList struct {
	data map[string]string
}

// NewEnvList creates a new EnvList
func NewEnvList() *EnvList {
	return &EnvList{data: make(map[string]string)}
}

// Put adds a key-value pair
func (el *EnvList) Put(key, value string) {
	el.data[key] = value
}

// Get retrieves a value by key
func (el *EnvList) Get(key string) string {
	return el.data[key]
}

func (el *EnvList) AllItems() map[string]string {
	return el.data
}

// GetEnvKeyNBForceRelay Exports the environment variable for the iOS client
func GetEnvKeyNBForceRelay() string {
	return peer.EnvKeyNBForceRelay
}
