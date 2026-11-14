//go:build !windows

package net

import (
	"context"
	"net"
)

func (d *Dialer) dialAdvanced(ctx context.Context, network, address string) (net.Conn, error) {
	return d.Dialer.DialContext(ctx, network, address)
}
