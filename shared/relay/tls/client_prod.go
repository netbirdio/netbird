//go:build !devcert

package tls

import (
	"crypto/tls"

	"github.com/netbirdio/netbird/util"
)

func ClientQUICTLSConfig() *tls.Config {
	return &tls.Config{
		NextProtos: []string{NBalpn},
		RootCAs:    util.GetGlobalCertPool(),
	}
}
