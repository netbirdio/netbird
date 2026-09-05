package middleware

import (
	"fmt"
	"sync"
)

// Registry maps middleware IDs to their factories. The proxy installs
// a single Registry at boot; concrete middlewares register themselves
// from init() functions inside their own packages so the boot wiring
// only needs an anonymous import.
//
// Registry is safe for concurrent reads after boot. Register / Unregister
// take the write lock; Get and IDs take the read lock.
type Registry struct {
	mu        sync.RWMutex
	factories map[string]Factory
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{factories: make(map[string]Factory)}
}

// Register installs the factory under its ID. Returns an error when an
// ID is already registered — collisions are programmer errors and must
// be visible at boot rather than silently last-write-wins.
func (r *Registry) Register(f Factory) error {
	if f == nil {
		return fmt.Errorf("middleware registry: nil factory")
	}
	id := f.ID()
	if id == "" {
		return fmt.Errorf("middleware registry: factory has empty id")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.factories[id]; exists {
		return fmt.Errorf("middleware registry: %q already registered", id)
	}
	r.factories[id] = f
	return nil
}

// MustRegister panics on error. Intended for init() registration so
// duplicate IDs surface at startup.
func (r *Registry) MustRegister(f Factory) {
	if err := r.Register(f); err != nil {
		panic(err)
	}
}

// Get returns the factory for id, or nil when no factory is
// registered.
func (r *Registry) Get(id string) Factory {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.factories[id]
}

// IDs returns the registered IDs in unspecified order. Used by the
// management translator to reject specs that reference unknown IDs at
// apply time.
func (r *Registry) IDs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.factories))
	for id := range r.factories {
		out = append(out, id)
	}
	return out
}

// IsKnown reports whether id has a registered factory.
func (r *Registry) IsKnown(id string) bool {
	return r.Get(id) != nil
}

// Resolver wraps a Registry and produces a configured Middleware
// instance from a Spec. The Manager uses this during chain build.
type Resolver struct {
	registry *Registry
}

// NewResolver returns a resolver backed by the registry.
func NewResolver(registry *Registry) *Resolver {
	if registry == nil {
		registry = NewRegistry()
	}
	return &Resolver{registry: registry}
}

// Resolve builds a Middleware instance and merges runtime-only fields
// (version, accepted content types, metadata key allowlist, mutation
// support) onto the spec.
//
// Return semantics:
//   - (mw, mergedSpec, nil): instance built, include in chain.
//   - (nil, spec, nil): id not registered; silently skip.
//   - (nil, spec, err): factory rejected the config (logged + counted
//     by Manager, other middlewares still bind).
func (r *Resolver) Resolve(spec Spec) (Middleware, Spec, error) {
	f := r.registry.Get(spec.ID)
	if f == nil {
		return nil, spec, nil
	}
	mw, err := f.New(spec.RawConfig)
	if err != nil {
		return nil, spec, fmt.Errorf("middleware %s factory: %w", spec.ID, err)
	}
	if mw.Slot() != spec.Slot {
		_ = mw.Close()
		return nil, spec, fmt.Errorf("middleware %s slot mismatch: spec=%d impl=%d", spec.ID, spec.Slot, mw.Slot())
	}
	merged := spec
	merged.Version = mw.Version()
	merged.MetadataKeys = append([]string(nil), mw.MetadataKeys()...)
	merged.AcceptedContentTypes = append([]string(nil), mw.AcceptedContentTypes()...)
	merged.MutationsSupported = mw.MutationsSupported()
	return mw, merged, nil
}
