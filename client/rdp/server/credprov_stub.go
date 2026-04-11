//go:build !windows

package server

// RegisterCredentialProvider is a no-op on non-Windows platforms.
func RegisterCredentialProvider() error {
	return nil
}

// UnregisterCredentialProvider is a no-op on non-Windows platforms.
func UnregisterCredentialProvider() error {
	return nil
}
