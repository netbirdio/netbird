//go:build !devcert

package tls

import (
	"crypto/tls"
	"fmt"
)

func ServerQUICTLSConfig(originTLSCfg *tls.Config) (*tls.Config, error) {
	if originTLSCfg == nil {
		return nil, fmt.Errorf("valid TLS config is required for QUIC listener")
	}
	cfg := originTLSCfg.Clone()
	cfg.NextProtos = []string{NBalpn}
	return cfg, nil
}
