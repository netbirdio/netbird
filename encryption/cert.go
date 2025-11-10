package encryption

import (
	"crypto/tls"
	"fmt"
)

// LoadTLSConfig loads a TLS configuration from certificate and key files.
// Security: This function enforces secure TLS defaults including:
// - Minimum TLS version 1.2 (TLS 1.0 and 1.1 are insecure and deprecated)
// - PreferServerCipherSuites for better security
// - Secure cipher suite selection
//
// Parameters:
//   - certFile: Path to the certificate file
//   - keyFile: Path to the private key file
//
// Returns:
//   - A configured TLS config with secure defaults
//   - An error if certificate/key loading fails
func LoadTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	serverCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
	}

	// Security: Enforce secure TLS defaults
	config := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.NoClientCert,
		// Security: Enforce minimum TLS version 1.2 (TLS 1.0 and 1.1 are insecure)
		MinVersion: tls.VersionTLS12,
		// Security: Prefer server cipher suites for better security
		PreferServerCipherSuites: true,
		NextProtos: []string{
			"h2", "http/1.1", // enable HTTP/2
		},
		// Security: Use secure cipher suites only
		// This ensures only strong ciphers are used
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
	}
	return config, nil
}
