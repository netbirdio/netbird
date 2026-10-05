// Package syncstore stores the latest Management sync response (which carries
// the network map) for debug bundle generation.
//
// The storage backend is selected at build time per operating system: on iOS
// the response is serialized to disk to keep it out of the (tightly
// constrained) process memory, while on all other platforms it is kept in
// memory. The backend is chosen by the New constructor; see factory_ios.go and
// factory_other.go.
package syncstore

import (
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

// Store persists the latest sync response and returns it on demand.
//
// Implementations must be safe for concurrent use.
type Store interface {
	// Set stores the given sync response, replacing any previously stored one.
	Set(resp *mgmProto.SyncResponse) error

	// Get returns the stored sync response, or nil if none is stored.
	// The returned value is an independent copy that the caller may retain.
	Get() (*mgmProto.SyncResponse, error)

	// Clear removes any stored sync response. It is safe to call when nothing
	// is stored.
	Clear() error
}
