package hooks

import (
	"net/netip"
	"slices"
	"sync"

	"github.com/google/uuid"
)

// ConnectionID provides a globally unique identifier for network connections.
// It's used to track connections throughout their lifecycle so the close hook can correlate with the dial hook.
type ConnectionID string

// GenerateConnID generates a unique identifier for each connection.
func GenerateConnID() ConnectionID {
	return ConnectionID(uuid.NewString())
}

type WriteHookFunc func(connID ConnectionID, prefix netip.Prefix) error
type CloseHookFunc func(connID ConnectionID) error
type AddressRemoveHookFunc func(connID ConnectionID, prefix netip.Prefix) error

var (
	hooksMutex sync.RWMutex

	writeHooks         []WriteHookFunc
	closeHooks         []CloseHookFunc
	addressRemoveHooks []AddressRemoveHookFunc
)

// AddWriteHook allows adding a new hook to be executed before writing/dialing.
func AddWriteHook(hook WriteHookFunc) {
	hooksMutex.Lock()
	defer hooksMutex.Unlock()
	writeHooks = append(writeHooks, hook)
}

// AddCloseHook allows adding a new hook to be executed on connection close.
func AddCloseHook(hook CloseHookFunc) {
	hooksMutex.Lock()
	defer hooksMutex.Unlock()
	closeHooks = append(closeHooks, hook)
}

// RemoveWriteHooks removes all write hooks.
func RemoveWriteHooks() {
	hooksMutex.Lock()
	defer hooksMutex.Unlock()
	writeHooks = nil
}

// RemoveCloseHooks removes all close hooks.
func RemoveCloseHooks() {
	hooksMutex.Lock()
	defer hooksMutex.Unlock()
	closeHooks = nil
}

// AddAddressRemoveHook allows adding a new hook to be executed when an address is removed.
func AddAddressRemoveHook(hook AddressRemoveHookFunc) {
	hooksMutex.Lock()
	defer hooksMutex.Unlock()
	addressRemoveHooks = append(addressRemoveHooks, hook)
}

// RemoveAddressRemoveHooks removes all listener address hooks.
func RemoveAddressRemoveHooks() {
	hooksMutex.Lock()
	defer hooksMutex.Unlock()
	addressRemoveHooks = nil
}

// GetWriteHooks returns a copy of the current write hooks.
func GetWriteHooks() []WriteHookFunc {
	hooksMutex.RLock()
	defer hooksMutex.RUnlock()
	return slices.Clone(writeHooks)
}

// GetCloseHooks returns a copy of the current close hooks.
func GetCloseHooks() []CloseHookFunc {
	hooksMutex.RLock()
	defer hooksMutex.RUnlock()
	return slices.Clone(closeHooks)
}

// GetAddressRemoveHooks returns a copy of the current listener address remove hooks.
func GetAddressRemoveHooks() []AddressRemoveHookFunc {
	hooksMutex.RLock()
	defer hooksMutex.RUnlock()
	return slices.Clone(addressRemoveHooks)
}
