package main

import "crypto/tls"

// insecureTLSConfig is isolated here so the linter can flag the single call
// site if we ever audit the tool. Only used when the operator explicitly
// passes --insecure (dev / self-signed cert scenarios).
func insecureTLSConfig() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true} //nolint:gosec // opt-in dev flag
}
