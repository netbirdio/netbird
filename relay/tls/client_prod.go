//go:build !devcert

package tls

import (
	"crypto/tls"
	"crypto/x509"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/util/embeddedroots"
)

func ClientQUICTLSConfig() *tls.Config {
	certPool, err := x509.SystemCertPool()
	if err != nil || certPool == nil {
		log.Debugf("System cert pool not available; falling back to embedded cert, error: %v", err)
		certPool = embeddedroots.Get()
	}

	return &tls.Config{
		NextProtos: []string{nbalpn},
		RootCAs:    certPool,
	}
}
