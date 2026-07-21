//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"

	"github.com/netbirdio/netbird/client/proto"
)

// Approval forwards the user's decision on a pending inbound-connection
// approval prompt to the daemon. The daemon pushes the prompt as a SystemEvent
// with category APPROVAL; the dialog calls Respond with the same request id to
// unblock whichever subsystem (VNC, SSH, ...) is waiting.
type Approval struct {
	conn DaemonConn
}

func NewApproval(conn DaemonConn) *Approval {
	return &Approval{conn: conn}
}

// Respond delivers the accept/deny decision for requestID. viewOnly is only
// meaningful when accept is true and the subsystem supports a read-only grant.
func (a *Approval) Respond(ctx context.Context, requestID string, accept, viewOnly bool) error {
	cli, err := a.conn.Client()
	if err != nil {
		return err
	}
	_, err = cli.RespondApproval(ctx, &proto.RespondApprovalRequest{
		RequestId: requestID,
		Accept:    accept,
		ViewOnly:  viewOnly,
	})
	return err
}
