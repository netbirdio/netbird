//go:build devcert

package tls

import (
	"crypto/tls"

	"github.com/netbirdio/netbird/util"
)

func ClientQUICTLSConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,             // Debug mode allows insecure connections
		NextProtos:         []string{NBalpn}, // Ensure this matches the server's ALPN
		RootCAs:            util.GetGlobalCertPool(),
	}
}
