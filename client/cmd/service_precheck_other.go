//go:build !windows && !ios && !android

package cmd

// checkNamedServiceFree is a no-op: named installations exist only on Windows.
func checkNamedServiceFree() error {
	return nil
}
