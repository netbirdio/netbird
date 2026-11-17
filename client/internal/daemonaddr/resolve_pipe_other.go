//go:build !windows

package daemonaddr

// ResolveDaemonAddr is a no-op off Windows, where there is no named-pipe
// default to fall back from.
func ResolveDaemonAddr(addr string) string {
	return addr
}
