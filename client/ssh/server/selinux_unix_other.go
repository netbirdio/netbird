//go:build unix && !linux

package server

// sessionExecContext has nothing to resolve on platforms without SELinux.
func sessionExecContext(string, []string) (string, error) {
	return "", nil
}

// setExecContext is a no-op on platforms without SELinux.
func setExecContext(string) error {
	return nil
}
