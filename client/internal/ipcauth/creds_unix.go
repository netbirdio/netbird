//go:build linux || darwin || freebsd

package ipcauth

import (
	"context"
	"net"

	"google.golang.org/grpc/credentials"
)

// NewTransportCredentials returns gRPC transport credentials that expose the
// caller's kernel-authenticated identity via IdentityFromContext. It returns
// nil on platforms that have no peer-identity primitive, which the caller must
// treat as "authorization cannot be enforced".
//
// The handshake exchanges no bytes on the wire, so a client dialing with
// insecure credentials interoperates with a server using these. That keeps
// older CLI and UI binaries working against an upgraded daemon.
func NewTransportCredentials() credentials.TransportCredentials {
	return unixCreds{}
}

// ConnIdentity extracts the caller's identity from an accepted local IPC
// connection. It is shared by the gRPC transport credentials and by the JSON
// gateway, which reads the identity of its own HTTP clients.
func ConnIdentity(conn net.Conn) (Identity, error) {
	return PeerIdentity(conn)
}

type unixCreds struct{}

func (unixCreds) ClientHandshake(_ context.Context, _ string, conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return conn, AuthInfo{}, nil
}

// ServerHandshake extracts the peer identity and fails closed when it cannot
// be read, so a connection whose caller is unknown never reaches a handler.
func (unixCreds) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	id, err := ConnIdentity(conn)
	if err != nil {
		return nil, nil, err
	}
	return conn, AuthInfo{
		CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.NoSecurity},
		Identity:       id,
	}, nil
}

func (unixCreds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: AuthInfo{}.AuthType()}
}

func (unixCreds) Clone() credentials.TransportCredentials { return unixCreds{} }

func (unixCreds) OverrideServerName(string) error { return nil }
