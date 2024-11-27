//go:build !dev

package tls

import "crypto/tls"

func ClientQUICTLSConfig() *tls.Config {
	return &tls.Config{
		NextProtos: []string{nbalpn},
	}
}
