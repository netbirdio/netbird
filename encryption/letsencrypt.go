package encryption

import (
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/acme/autocert"
)

// CreateCertManager wraps common logic of generating Let's encrypt certificate.
func CreateCertManager(datadir string, letsencryptDomain string) (*autocert.Manager, error) {
	certDir := filepath.Join(datadir, "letsencrypt")

	if _, err := os.Stat(certDir); os.IsNotExist(err) {
		err = os.MkdirAll(certDir, 0755)
		if err != nil {
			return nil, err
		}
	}

	log.Infof("running with LetsEncrypt (%s). Cert will be stored in %s", letsencryptDomain, certDir)

	certManager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(certDir),
		HostPolicy: autocert.HostWhitelist(letsencryptDomain),
	}

	return certManager, nil
}
