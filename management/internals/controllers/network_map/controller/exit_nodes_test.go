package controller

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/management/internals/modules/exitnodes"
	"github.com/netbirdio/netbird/management/internals/shared/db"
)

// cancellableLister fails like the SQL repository does once its context is cancelled.
type cancellableLister struct {
	nodes []*exitnodes.ExitNode
}

func (l cancellableLister) ListByAccount(ctx context.Context, _ db.LockingStrength, _ string) ([]*exitnodes.ExitNode, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return l.nodes, nil
}

func TestAccountExitNodes_IgnoresRequestCancellation(t *testing.T) {
	node := &exitnodes.ExitNode{ID: "exit-node-1", AccountID: "account-1", Enabled: true}
	c := &Controller{}
	c.SetExitNodes(cancellableLister{nodes: []*exitnodes.ExitNode{node}})

	// The HTTP request behind an exit node write can be cancelled while the account path
	// builds the maps it then sends to every peer.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	assert.Equal(t, []*exitnodes.ExitNode{node}, c.accountExitNodes(ctx, "account-1"),
		"a cancelled request should not send network maps without the account's exit nodes")
}
