//go:build !darwin && !windows

package certproof

import (
	"os"

	log "github.com/sirupsen/logrus"
)

// DefaultStore is the PEM directory named by NB_CERT_STORE_DIR, or /etc/netbird/certs,
// joined by the PKCS#11 token named by NB_CERT_PKCS11_URI when that is set.
func DefaultStore() Store {
	files := NewFileStore(StoreDir())
	uri := os.Getenv(PKCS11URIEnv)
	if uri == "" {
		return files
	}
	token, err := NewPKCS11Store(uri)
	if err != nil {
		log.Warnf("ignoring %s: %v", PKCS11URIEnv, err)
		return files
	}
	return Stores{files, token}
}
