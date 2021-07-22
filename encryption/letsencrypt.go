package encryption

import (
	"crypto/tls"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/acme/autocert"
	"net/http"
	"os"
	"path/filepath"
)

// EnableLetsEncrypt wraps common logic of generating Let's encrypt certificate.
// Includes a HTTP handler and listener to solve the Let's encrypt challenge
func EnableLetsEncrypt(datadir string, letsencryptDomain string) *tls.Config {
	certDir := filepath.Join(datadir, "letsencrypt")

	if _, err := os.Stat(certDir); os.IsNotExist(err) {
		err = os.MkdirAll(certDir, os.ModeDir)
		if err != nil {
			log.Fatalf("failed creating Let's encrypt certdir: %s: %v", certDir, err)
		}
	}

	log.Infof("running with Let's encrypt with domain %s. Cert will be stored in %s", letsencryptDomain, certDir)

	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(certDir),
		HostPolicy: autocert.HostWhitelist(letsencryptDomain),
	}

	// listener to handle Let's encrypt certificate challenge
	go func() {
		if err := http.Serve(certManager.Listener(), certManager.HTTPHandler(nil)); err != nil {
			log.Fatalf("failed to serve letsencrypt handler: %v", err)
		}
	}()

	return &tls.Config{GetCertificate: certManager.GetCertificate}
}
