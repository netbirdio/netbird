package mcpapi

import (
	"context"
	"slices"
	"strings"
	"unicode"

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
	if name := auditClientName(e.clientName); name != "" {
		meta["client_name"] = name
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

// hiddenRunes render as nothing or move the text around them: format characters such as bidi
// overrides and zero-width spaces, line and paragraph separators, variation selectors and the
// other default-ignorable code points such as Hangul fillers.
var hiddenRunes = []*unicode.RangeTable{
	unicode.Cf, unicode.Zl, unicode.Zp, unicode.Variation_Selector, unicode.Other_Default_Ignorable_Code_Point,
}

// auditClientName drops control and hidden characters, which a self-chosen name could use to
// reorder or hide text where the log is shown.
func auditClientName(name string) string {
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.In(r, hiddenRunes...) {
			return -1
		}
		return r
	}, name))
}

// accessGranted names the scopes the user approved at consent. The user's role still limits
// the session, so "read and write" does not mean the user may write.
func accessGranted(scopes []string) string {
	if slices.Contains(scopes, scopeWrite) {
		return "read and write"
	}
	return "read"
}
