package owner

import (
	"fmt"
	"sync"
)

// ConfigAdapter is a thread-safe OwnerConfig that delegates to a lazily-set backend.
// This allows the interceptor to be created before the daemon server (and its config)
// is initialized, which is necessary because gRPC interceptors are set at server creation time.
type ConfigAdapter struct {
	mu      sync.RWMutex
	backend OwnerConfig
}

// SetBackend sets the actual config implementation. Must be called before any RPCs are served.
func (a *ConfigAdapter) SetBackend(backend OwnerConfig) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.backend = backend
}

// GetOwnerUIDs delegates to the backend.
func (a *ConfigAdapter) GetOwnerUIDs() []UID {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.backend == nil {
		// No backend yet, return empty (root-only).
		return []UID{}
	}

	return a.backend.GetOwnerUIDs()
}

// AddOwnerUID delegates to the backend.
func (a *ConfigAdapter) AddOwnerUID(uid UID) error {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.backend == nil {
		return fmt.Errorf("owner config backend not initialized")
	}

	return a.backend.AddOwnerUID(uid)
}
