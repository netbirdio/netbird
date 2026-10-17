//go:build js || plan9

package profilemanager

// lockPrefsFile is a no-op where there is no file locking to reach for:
// syscall.Flock does not exist on js/wasm or plan9. Neither runs the mobile
// clients, which is where a second process writes these files, so the
// in-process mutex around the read-modify-write is the whole guarantee there
// — the same one this package had before the lock was introduced.
func lockPrefsFile(string) (func(), error) {
	return func() {}, nil
}
