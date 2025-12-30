//go:build !((darwin && !ios) || dragonfly || freebsd || netbsd || openbsd)

package systemops

// FlushMarkedRoutes is a no-op on non-BSD platforms.
func (r *SysOps) FlushMarkedRoutes() error {
	return nil
}
