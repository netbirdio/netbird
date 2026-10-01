// Package tls provides utilities for configuring and managing Transport Layer
// Security (TLS) in server and client environments, with a focus on QUIC
// protocol support and testing configurations.
//
// The package includes functions for cloning and customizing TLS
// configurations as well as generating self-signed certificates for
// development and testing purposes.
//
// Key Features:
//
//   - `ServerQUICTLSConfig`: Creates a server-side TLS configuration tailored
//     for QUIC protocol with specified or default settings. QUIC requires a
//     specific TLS configuration with proper ALPN (Application-Layer Protocol
//     Negotiation) support, making the TLS settings crucial for establishing
//     secure connections.
//
//   - `ClientQUICTLSConfig`: Provides a client-side TLS configuration suitable
//     for QUIC protocol. The configuration differs between development
//     (insecure testing) and production (strict verification).
//
//   - `generateTestTLSConfig`: Generates a self-signed TLS configuration for
//     use in local development and testing scenarios.
//
// Usage:
//
// This package provides separate implementations for development and production
// environments. The development implementation (guarded by `//go:build devcert`)
// supports testing configurations with self-signed certificates and insecure
// client connections. The production implementation (guarded by `//go:build
// !devcert`) ensures that valid and secure TLS configurations are supplied
// and used.
//
// The QUIC protocol is highly reliant on properly configured TLS settings,
// and this package ensures that configurations meet the requirements for
// secure and efficient QUIC communication.
package tls
