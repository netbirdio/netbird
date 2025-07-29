package hooks

import (
	"context"
	"net"
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

type DialerDialHookFunc func(ctx context.Context, connID ConnectionID, resolvedAddresses []net.IPAddr) error
type DialerCloseHookFunc func(connID ConnectionID, conn *net.Conn) error
type ListenerWriteHookFunc func(connID ConnectionID, ip *net.IPAddr, data []byte) error
type ListenerCloseHookFunc func(connID ConnectionID, conn net.PacketConn) error
type ListenerAddressRemoveHookFunc func(connID ConnectionID, prefix netip.Prefix) error

var (
	hooksMutex sync.RWMutex

	dialerDialHooks            []DialerDialHookFunc
	dialerCloseHooks           []DialerCloseHookFunc
	listenerWriteHooks         []ListenerWriteHookFunc
	listenerCloseHooks         []ListenerCloseHookFunc
	listenerAddressRemoveHooks []ListenerAddressRemoveHookFunc
)

// AddDialerHook allows adding a new hook to be executed before dialing.
func AddDialerHook(hook DialerDialHookFunc) {
	hooksMutex.Lock()
	defer hooksMutex.Unlock()
	dialerDialHooks = append(dialerDialHooks, hook)
}

// AddDialerCloseHook allows adding a new hook to be executed on connection close.
func AddDialerCloseHook(hook DialerCloseHookFunc) {
	hooksMutex.Lock()
	defer hooksMutex.Unlock()
	dialerCloseHooks = append(dialerCloseHooks, hook)
}

// RemoveDialerHooks removes all dialer hooks.
func RemoveDialerHooks() {
	hooksMutex.Lock()
	defer hooksMutex.Unlock()
	dialerDialHooks = nil
	dialerCloseHooks = nil
}

// AddListenerWriteHook allows adding a new write hook to be executed before a UDP packet is sent.
func AddListenerWriteHook(hook ListenerWriteHookFunc) {
	hooksMutex.Lock()
	defer hooksMutex.Unlock()
	listenerWriteHooks = append(listenerWriteHooks, hook)
}

// AddListenerCloseHook allows adding a new hook to be executed upon closing a UDP connection.
func AddListenerCloseHook(hook ListenerCloseHookFunc) {
	hooksMutex.Lock()
	defer hooksMutex.Unlock()
	listenerCloseHooks = append(listenerCloseHooks, hook)
}

// AddListenerAddressRemoveHook allows adding a new hook to be executed when an address is removed.
func AddListenerAddressRemoveHook(hook ListenerAddressRemoveHookFunc) {
	hooksMutex.Lock()
	defer hooksMutex.Unlock()
	listenerAddressRemoveHooks = append(listenerAddressRemoveHooks, hook)
}

// RemoveListenerHooks removes all listener hooks.
func RemoveListenerHooks() {
	hooksMutex.Lock()
	defer hooksMutex.Unlock()
	listenerWriteHooks = nil
	listenerCloseHooks = nil
	listenerAddressRemoveHooks = nil
}

// GetDialerHooks returns a copy of the current dialer dial hooks.
func GetDialerHooks() []DialerDialHookFunc {
	hooksMutex.RLock()
	defer hooksMutex.RUnlock()
	return slices.Clone(dialerDialHooks)
}

// GetDialerCloseHooks returns a copy of the current dialer close hooks.
func GetDialerCloseHooks() []DialerCloseHookFunc {
	hooksMutex.RLock()
	defer hooksMutex.RUnlock()
	return slices.Clone(dialerCloseHooks)
}

// GetListenerWriteHooks returns a copy of the current listener write hooks.
func GetListenerWriteHooks() []ListenerWriteHookFunc {
	hooksMutex.RLock()
	defer hooksMutex.RUnlock()
	return slices.Clone(listenerWriteHooks)
}

// GetListenerCloseHooks returns a copy of the current listener close hooks.
func GetListenerCloseHooks() []ListenerCloseHookFunc {
	hooksMutex.RLock()
	defer hooksMutex.RUnlock()
	return slices.Clone(listenerCloseHooks)
}

// GetListenerAddressRemoveHooks returns a copy of the current listener address remove hooks.
func GetListenerAddressRemoveHooks() []ListenerAddressRemoveHookFunc {
	hooksMutex.RLock()
	defer hooksMutex.RUnlock()
	return slices.Clone(listenerAddressRemoveHooks)
}
