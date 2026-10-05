//go:build ((!darwin && !windows) || ios) && !js

package certproof

import (
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/pkcs11"
)

var unsupportedTokenOnce sync.Once

// DefaultStore is the PEM directory named by NB_CERT_STORE_DIR, or /etc/netbird/certs.
func DefaultStore() Store {
	return NewFileStore(StoreDir())
}

// storeWithToken reads the PEM directory cfg names, joined by the PKCS#11 token when cfg
// names one. The token pairs the directory's key-less certificates with its own keys.
func storeWithToken(cfg Config) Store {
	files := NewFileStore(cfg.dir())
	if cfg.PKCS11.URI == "" && cfg.PKCS11.PIN == "" {
		return files
	}
	if !pkcs11.Supported() {
		unsupportedTokenOnce.Do(func() {
			log.Warnf("ignoring the configured PKCS#11 token: %v", pkcs11.ErrUnsupported)
		})
		return files
	}
	token, err := NewPKCS11Store(cfg.PKCS11, cfg.dir())
	if err != nil {
		log.Warnf("ignoring PKCS#11 URI: %v", err)
		return files
	}
	return Stores{files, token}
}
