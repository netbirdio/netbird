//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"

	log "github.com/sirupsen/logrus"

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
	resp, err := cli.RespondApproval(ctx, &proto.RespondApprovalRequest{
		RequestId: requestID,
		Accept:    accept,
		ViewOnly:  viewOnly,
	})
	if err != nil {
		return err
	}
	if !resp.GetMatched() {
		// Not an error to the caller: the dialog closes either way. The daemon
		// does not say which of "already answered", "expired" or "never known"
		// applies, so neither does this line; it exists so a report of "I
		// clicked and nothing happened" has a record that the click reached a
		// prompt that was no longer waiting.
		log.Infof("approval %s was no longer pending; this response changed nothing", requestID)
	}
	return nil
}
