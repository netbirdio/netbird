//go:build !devcert

package tls

import (
	"crypto/tls"
	"fmt"
)

// DevCertHash returns nil in production builds. It exists so callers (notably
// the WASM WebTransport dialer) can probe for a self-signed dev cert hash
// without branching on build tags.
func DevCertHash() []byte { return nil }

func ServerQUICTLSConfig(originTLSCfg *tls.Config) (*tls.Config, error) {
	if originTLSCfg == nil {
		return nil, fmt.Errorf("valid TLS config is required for QUIC listener")
	}
	cfg := originTLSCfg.Clone()
	cfg.NextProtos = []string{NBalpn}
	return cfg, nil
}

// ServerMuxTLSConfig returns a TLS config that advertises both the raw QUIC
// relay ALPN and HTTP/3. The ALPN-multiplexing UDP listener uses it to share a
// single socket between raw QUIC clients and WebTransport (browser) clients.
func ServerMuxTLSConfig(originTLSCfg *tls.Config) (*tls.Config, error) {
	if originTLSCfg == nil {
		return nil, fmt.Errorf("valid TLS config is required for QUIC/WT listener")
	}
	cfg := originTLSCfg.Clone()
	cfg.NextProtos = []string{NBalpn, H3alpn}
	return cfg, nil
}
