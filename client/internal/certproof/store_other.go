//go:build !darwin && !windows

package certproof

import log "github.com/sirupsen/logrus"

// DefaultStore is the PEM directory named by NB_CERT_STORE_DIR, or /etc/netbird/certs.
func DefaultStore() Store {
	return NewFileStore(StoreDir())
}

// storeWithToken joins DefaultStore with the PKCS#11 token cfg names, when it names one.
func storeWithToken(cfg PKCS11Config) Store {
	files := DefaultStore()
	if cfg.URI == "" && cfg.PIN == "" {
		return files
	}
	token, err := NewPKCS11Store(cfg)
	if err != nil {
		log.Warnf("ignoring PKCS#11 URI: %v", err)
		return files
	}
	return Stores{files, token}
}
