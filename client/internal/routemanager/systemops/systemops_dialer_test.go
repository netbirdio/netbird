//go:build !android && !ios

package systemops

import (
	"context"
	"net"
)

// dialer is shared by the per-platform routing test cases. Kept untagged (no
// privileged build tag) so the non-privileged test files compile on every platform.
//
//nolint:unused // consumed by the privileged-tagged routing tests
type dialer interface {
	Dial(network, address string) (net.Conn, error)
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}
