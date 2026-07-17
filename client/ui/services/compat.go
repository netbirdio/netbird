//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/proto"
)

// Compat answers whether the running daemon is new enough to drive this UI.
type Compat struct {
	conn DaemonConn
}

func NewCompat(conn DaemonConn) *Compat {
	return &Compat{conn: conn}
}

// DaemonReady probes the WailsUIReady RPC once. A true result means the daemon
// implements it and is compatible. An Unimplemented response means the daemon
// predates this UI and is too old; the caller should surface an upgrade prompt.
// Any other error (daemon not running, transport failure) is returned so the
// frontend can tell "outdated" apart from "not reachable".
func (c *Compat) DaemonReady(ctx context.Context) (bool, error) {
	client, err := c.conn.Client()
	if err != nil {
		return false, err
	}
	if _, err := client.WailsUIReady(ctx, &proto.WailsUIReadyRequest{}); err != nil {
		if st, ok := status.FromError(err); ok && st.Code() == codes.Unimplemented {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
