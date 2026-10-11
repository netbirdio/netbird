//go:build !unix

package certproof

import (
	"fmt"
	"io"
	"os"
)

// readStoreFile reads a certificate or key file of the PEM directory, up to the size
// limit. Ownership is checked on Unix only; elsewhere the PEM directory is not the store
// the daemon reads by default.
func readStoreFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	data, err := io.ReadAll(io.LimitReader(f, maxStoreFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) > maxStoreFileSize {
		return nil, fmt.Errorf("%s is over the %d byte limit", path, maxStoreFileSize)
	}
	return data, nil
}

// checkStoreDir accepts any directory where the PEM directory is not a default store.
func checkStoreDir(string) error {
	return nil
}
