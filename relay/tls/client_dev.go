//go:build devcert

package tls

import "crypto/tls"

func ClientQUICTLSConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,             // Debug mode allows insecure connections
		NextProtos:         []string{nbalpn}, // Ensure this matches the server's ALPN
	}
}
