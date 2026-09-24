package ipcauth

import "context"

// Target is the profile a request resolved to.
type Target struct {
	Path  string
	Owned bool
	// UnOwned reports that the resolved profile records no owner.
	UnOwned bool
	// Handle is the resolved profile's ID, which a refusal names in the command
	// it hands the caller. A request that named nothing still has one.
	Handle string
}

type targetKey struct{}

// ContextWithTarget carries the profile the gate resolved, so a handler acts on
// the profile that was authorized rather than resolving the caller's handle a
// second time.
func ContextWithTarget(ctx context.Context, path string) context.Context {
	return context.WithValue(ctx, targetKey{}, path)
}

// TargetFromContext returns the file of the profile the gate resolved for this
// request. It reports false when nothing resolved, which a handler acting on a
// named profile must treat as a refusal rather than as the active profile.
func TargetFromContext(ctx context.Context) (string, bool) {
	path, ok := ctx.Value(targetKey{}).(string)
	return path, ok && path != ""
}
