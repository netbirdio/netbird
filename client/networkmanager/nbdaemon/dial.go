//go:build linux

// Package nbdaemon dials the netbird daemon's gRPC control socket, shared by
// nm-netbird-service and nm-netbird-auth-dialog since both need to talk to
// it independently (the latter to wait out the SSO login from the user's
// own session).
package nbdaemon

import (
	"fmt"

	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/client/internal/daemonaddr"
)

// DefaultAddr is the netbird daemon's default control socket on Linux,
// mirroring client/cmd/root.go's default.
const DefaultAddr = "unix:///var/run/netbird.sock"

// Dial connects to the netbird daemon over its control socket, using the
// same address resolution and dial options as the netbird CLI/UI.
func Dial() (*grpc.ClientConn, error) {
	addr := daemonaddr.ResolveUnixDaemonAddr(DefaultAddr)
	target, opts := daemonaddr.DialTarget(addr)

	conn, err := grpc.NewClient(target, opts...)
	if err != nil {
		return nil, fmt.Errorf("dial netbird daemon: %w", err)
	}
	return conn, nil
}
