package middleware

import "context"

// Middleware is the surface exposed by each concrete implementation.
// The Manager invokes it through the Dispatcher, passing a cloned
// Input. Each middleware lives in exactly one Slot.
//
// Close releases any resources owned by the middleware instance
// (background goroutines, file handles). It is invoked when the chain
// holding the middleware is replaced or torn down. Implementations
// must be idempotent and safe to call after construction even when
// Invoke was never called.
type Middleware interface {
	ID() string
	Version() string
	Slot() Slot

	// AcceptedContentTypes lists the request/response content types
	// the middleware needs the body for. Empty slice means the
	// middleware does not inspect the body.
	AcceptedContentTypes() []string

	// MetadataKeys is the closed set of metadata keys this middleware
	// may emit. The accumulator drops anything outside this allowlist.
	MetadataKeys() []string

	// MutationsSupported reports whether the middleware may emit
	// header / body mutations. A spec with CanMutate=true is honoured
	// only when the implementation also supports mutations.
	MutationsSupported() bool

	Invoke(ctx context.Context, in *Input) (*Output, error)

	Close() error
}

// Factory builds a configured Middleware instance from raw config
// bytes shipped on the wire. Each registered middleware ID has a
// single factory in the registry. Factory.New returns an error when
// the config is malformed or violates a per-middleware invariant; the
// chain build path logs the error, increments the resolve_error metric,
// and skips the middleware.
type Factory interface {
	ID() string
	New(rawConfig []byte) (Middleware, error)
}
