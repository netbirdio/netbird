//go:build (dragonfly || freebsd || netbsd || openbsd) && !darwin

package systemops

// Non-darwin BSDs don't support the IP_BOUND_IF + scoped default model. They
// always fall through to the ref-counter exclusion-route path; these stubs
// exist only so systemops_unix.go compiles.
func (r *SysOps) setupAdvancedRouting() error   { return nil }
func (r *SysOps) cleanupAdvancedRouting() error { return nil }
func (r *SysOps) flushPlatformExtras() error    { return nil }
