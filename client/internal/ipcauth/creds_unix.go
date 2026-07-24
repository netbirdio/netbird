//go:build linux || darwin || freebsd

package ipcauth

import (
	"context"
	"net"

	"google.golang.org/grpc/credentials"
)

// NewTransportCredentials returns gRPC transport credentials that extract the
// caller's kernel-authenticated identity from a Unix-socket connection and
// expose it via IdentityFromContext. Non-nil on platforms with a
// peer-credential primitive.
func NewTransportCredentials() credentials.TransportCredentials {
	return unixCreds{}
}

type unixCreds struct{}

func (unixCreds) ClientHandshake(_ context.Context, _ string, conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return conn, AuthInfo{}, nil
}

// ConnIdentity extracts the caller's identity from an accepted local IPC
// connection. On Unix it reads peer credentials from the socket. It is shared
// by the gRPC transport credentials and the JSON gateway (which forwards it).
func ConnIdentity(conn net.Conn) (Identity, error) {
	return PeerIdentity(conn)
}

// ServerHandshake extracts the peer identity and fails closed if it cannot be read.
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
