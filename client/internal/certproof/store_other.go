//go:build !darwin && !windows

package certproof

// DefaultStore is the PEM directory named by NB_CERT_STORE_DIR, or /etc/netbird/certs.
func DefaultStore() Store {
	return NewFileStore(StoreDir())
}
