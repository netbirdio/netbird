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

// unixCreds implements credentials.TransportCredentials over a Unix socket.
// The server side reads SO_PEERCRED/LOCAL_PEERCRED during the handshake; the
// client side is a no-op (the kernel supplies the peer identity to the server
// without any client cooperation), so an ordinary insecure client still works.
type unixCreds struct{}

func (unixCreds) ClientHandshake(_ context.Context, _ string, conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return conn, AuthInfo{}, nil
}

// ServerHandshake extracts the peer identity and fails closed if it cannot be read.
func (unixCreds) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	id, err := PeerIdentity(conn)
	if err != nil {
		return nil, nil, err
	}
	return conn, AuthInfo{
		CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.NoSecurity},
		Identity:       id,
	}, nil
}

func (unixCreds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "netbird-ipc-peercred"}
}

func (unixCreds) Clone() credentials.TransportCredentials { return unixCreds{} }

func (unixCreds) OverrideServerName(string) error { return nil }
