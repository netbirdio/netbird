package mcpapi

import (
	"context"
	"slices"

	"github.com/netbirdio/netbird/management/server/activity"
)

// sessionEvent is what the activity log records about an MCP session. clientName and
// redirectURI are empty where the request does not carry them: a revocation names its client
// only when it sends a client_id, and only a code holds the redirect URI.
type sessionEvent struct {
	identity    grantIdentity
	clientName  string
	redirectURI string
	scopes      []string
}

// recordSession stores an activity event with the session's user as initiator and target, in
// the account the user signed in to.
func (b *Broker) recordSession(ctx context.Context, code activity.Activity, e sessionEvent) {
	meta := map[string]any{"access": accessGranted(e.scopes)}
	if e.clientName != "" {
		meta["client_name"] = e.clientName
	}
	if e.redirectURI != "" {
		meta["redirect_host"] = redirectHost(e.redirectURI)
	}
	b.accounts.StoreEvent(ctx, e.identity.UserID, e.identity.UserID, e.identity.AccountID, code, meta)
}

// clientName is the name a client chose at registration, or "" when clientID is empty or was
// not issued by this broker.
func (b *Broker) clientName(clientID string) string {
	client, _ := b.lookupClient(clientID)
	return client.Name
}

func accessGranted(scopes []string) string {
	if slices.Contains(scopes, scopeWrite) {
		return "read and write"
	}
	return "read"
}
