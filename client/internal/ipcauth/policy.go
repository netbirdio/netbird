package ipcauth

import "sync"

const servicePath = "/daemon.DaemonService/"

// ProfilePolicy exposes ownership to the interceptor. The daemon server
// implements it. ConfigAdapter bridges the gap because the gRPC server (and its
// interceptor) is constructed before the server instance exists.
type ProfilePolicy interface {
	// ActiveProfileOwnership returns the active profile's ownership policy.
	ActiveProfileOwnership() Ownership

	// ClaimActiveProfileOwnerIfUnowned atomically claims the active profile for
	// id when it has no owners and is not shared (trust-on-first-use), and
	// reports whether id is now an owner. A false return means the profile was
	// already owned or shared or another caller won the claim.
	ClaimActiveProfileOwnerIfUnowned(id Identity) (bool, error)

	// DaemonOwnership returns the daemon-wide ownership policy that governs the
	// owner-tier RPCs and the default profile.
	DaemonOwnership() Ownership

	// ClaimDaemonOwnerIfUnowned atomically claims daemon-wide ownership for id
	// when the daemon is unowned and not shared (trust-on-first-use).
	ClaimDaemonOwnerIfUnowned(id Identity) (bool, error)
}

// ownersAuthorizedMethods gate on the daemon-wide owner set (or root): daemon-level
// ops independent of any profile. The owner-set mutations (AddOwner, ShareProfile,
// ResetOwner) must gate here, not on the active profile, else a per-profile owner
// could escalate via `owner add`. ResetOwner also requires root in its handler.
var ownersAuthorizedMethods = map[string]bool{
	servicePath + "AddProfile":   true,
	servicePath + "Down":         true,
	servicePath + "Status":       true,
	servicePath + "AddOwner":     true,
	servicePath + "ShareProfile": true,
	servicePath + "ResetOwner":   true,
}

// handlerAuthorizedMethods bypass the ownership gate (identity still required)
// and let the handler authorize. GetActiveProfile bypasses only to return
// public metadata any local user may read.
var handlerAuthorizedMethods = map[string]bool{
	servicePath + "ListProfiles":     true,
	servicePath + "RemoveProfile":    true,
	servicePath + "RenameProfile":    true,
	servicePath + "SwitchProfile":    true,
	servicePath + "GetActiveProfile": true,
}

// auditMethods are worth an audit log line. Denials are always logged.
var auditMethods = map[string]bool{
	servicePath + "GetConfig":          true,
	servicePath + "SetConfig":          true,
	servicePath + "Login":              true,
	servicePath + "WaitSSOLogin":       true,
	servicePath + "RequestJWTAuth":     true,
	servicePath + "WaitJWTToken":       true,
	servicePath + "StartCapture":       true,
	servicePath + "StartBundleCapture": true,
	servicePath + "DebugBundle":        true,
	servicePath + "ExposeService":      true,
	servicePath + "Up":                 true,
	servicePath + "Down":               true,
	servicePath + "SelectNetworks":     true,
	servicePath + "DeselectNetworks":   true,
	servicePath + "SwitchProfile":      true,
	servicePath + "TriggerUpdate":      true,
	servicePath + "Logout":             true,
	servicePath + "CleanState":         true,
	servicePath + "DeleteState":        true,
	servicePath + "AddOwner":           true,
	servicePath + "ResetOwner":         true,
	servicePath + "ShareProfile":       true,
}

// ConfigAdapter is a ProfilePolicy whose backend is set lazily, once the daemon
// server instance is created. Until then it reports an unowned profile
// (Ownership zero value), so non-privileged callers are denied.
type ConfigAdapter struct {
	mu      sync.RWMutex
	backend ProfilePolicy
}

// SetBackend installs the real policy. Must be called before serving RPCs.
func (a *ConfigAdapter) SetBackend(backend ProfilePolicy) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.backend = backend
}

// ActiveProfileOwnership delegates to the backend, or reports an unowned profile
// when no backend is set yet.
func (a *ConfigAdapter) ActiveProfileOwnership() Ownership {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.backend == nil {
		return Ownership{}
	}
	return a.backend.ActiveProfileOwnership()
}

// ClaimActiveProfileOwnerIfUnowned delegates to the backend. Before the backend
// is set it cannot claim, so it reports not-owned (fail closed).
func (a *ConfigAdapter) ClaimActiveProfileOwnerIfUnowned(id Identity) (bool, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.backend == nil {
		return false, nil
	}
	return a.backend.ClaimActiveProfileOwnerIfUnowned(id)
}

// DaemonOwnership delegates to the backend, reporting unowned when none is set.
func (a *ConfigAdapter) DaemonOwnership() Ownership {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.backend == nil {
		return Ownership{}
	}
	return a.backend.DaemonOwnership()
}

// ClaimDaemonOwnerIfUnowned delegates to the backend. Before the backend is set
// it cannot claim, so it reports not-owned (fail closed).
func (a *ConfigAdapter) ClaimDaemonOwnerIfUnowned(id Identity) (bool, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.backend == nil {
		return false, nil
	}
	return a.backend.ClaimDaemonOwnerIfUnowned(id)
}
