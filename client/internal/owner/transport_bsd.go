//go:build darwin || freebsd

package owner

import (
	"context"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc/credentials"
)

// NewUnixTransportCredentials returns gRPC TransportCredentials that extract
// peer UID from Unix socket connections via LOCAL_PEERCRED (Xucred).
func NewUnixTransportCredentials() credentials.TransportCredentials {
	return &unixCreds{}
}

type unixCreds struct{}

func (c *unixCreds) ClientHandshake(_ context.Context, _ string, conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return conn, UnixAuthInfo{}, nil
}

// ServerHandshake extracts peer credentials from the Unix connection using LOCAL_PEERCRED.
// Returns an error if credentials cannot be extracted (fail-closed).
func (c *unixCreds) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, nil, fmt.Errorf("expected *net.UnixConn, got %T", conn)
	}

	raw, err := uc.SyscallConn()
	if err != nil {
		return nil, nil, fmt.Errorf("get raw conn for peer credentials: %w", err)
	}

	var xucred *unix.Xucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		xucred, credErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return nil, nil, fmt.Errorf("control raw conn for peer credentials: %w", err)
	}
	if credErr != nil {
		return nil, nil, fmt.Errorf("get peer credentials: %w", credErr)
	}

	return conn, UnixAuthInfo{
		CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.NoSecurity},
		UID:            UID(xucred.Uid),
	}, nil
}

func (c *unixCreds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "unix_peercred"}
}

func (c *unixCreds) Clone() credentials.TransportCredentials {
	return &unixCreds{}
}

func (c *unixCreds) OverrideServerName(_ string) error {
	return nil
}
