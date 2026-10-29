//go:build !windows

package coexist

// addressChanges never signals: named installations, and with them secondary
// ones, exist only on Windows.
func addressChanges() (<-chan struct{}, func(), error) {
	return nil, func() {}, nil
}
