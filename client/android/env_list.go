package android

import (
	"github.com/netbirdio/netbird/client/internal/lazyconn"
	"github.com/netbirdio/netbird/client/internal/peer"
)

var (
	// EnvKeyNBForceRelay Exported for Android java client to force relay connections
	EnvKeyNBForceRelay = peer.EnvKeyNBForceRelay

	// EnvKeyNBLazyConn Exported for Android java client to configure lazy connection
	EnvKeyNBLazyConn = lazyconn.EnvEnableLazyConn

	// EnvKeyNBInactivityThreshold Exported for Android java client to configure connection inactivity threshold
	EnvKeyNBInactivityThreshold = lazyconn.EnvInactivityThreshold
)

// EnvList wraps a Go map for export to Java
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
