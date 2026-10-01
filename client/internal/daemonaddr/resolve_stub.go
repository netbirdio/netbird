//go:build windows || ios || android

package daemonaddr

// ResolveUnixDaemonAddr is a no-op on platforms that don't use Unix sockets.
func ResolveUnixDaemonAddr(addr string) string {
	return addr
}
