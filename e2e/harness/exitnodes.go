//go:build e2e

package harness

import (
	"context"
	"net/http"
	"net/url"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

// The shared REST client has no exit node methods, so these drive /api/exit-nodes
// through the same request helper the agent-network endpoints use.

// CreateExitNode creates an exit node.
func (c *Combined) CreateExitNode(ctx context.Context, req api.ExitNodeRequest) (api.ExitNode, error) {
	return anRequest[api.ExitNode](ctx, c, http.MethodPost, "/api/exit-nodes", req)
}

// GetExitNode returns an exit node.
func (c *Combined) GetExitNode(ctx context.Context, id string) (api.ExitNode, error) {
	return anRequest[api.ExitNode](ctx, c, http.MethodGet, exitNodePath(id), nil)
}

// UpdateExitNode replaces an exit node.
func (c *Combined) UpdateExitNode(ctx context.Context, id string, req api.ExitNodeRequest) (api.ExitNode, error) {
	return anRequest[api.ExitNode](ctx, c, http.MethodPut, exitNodePath(id), req)
}

// DeleteExitNode deletes an exit node and the policies whose destination it is.
func (c *Combined) DeleteExitNode(ctx context.Context, id string) error {
	return anDelete(ctx, c, exitNodePath(id))
}

func exitNodePath(id string) string {
	return "/api/exit-nodes/" + url.PathEscape(id)
}
