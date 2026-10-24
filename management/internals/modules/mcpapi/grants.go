package mcpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
)

// A grant is the server-side record of one login: the session a code redemption starts.
// Tokens stay sealed values, but each carries its grant's ID, and a token whose grant is gone
// is refused. That makes a session revocable on its own and lets the broker enforce the
// OAuth 2.1 rules a stateless server cannot: single-use codes and refresh token rotation.
//
// The records live in Redis whenever management's shared cache does, which it must when
// management runs as more than one instance. Losing them, to a flush or to a single
// instance's restart, signs MCP clients out; it never lets a token through.
const (
	grantKeyPrefix     = "mcp-oauth:session:"
	usedCodeKeyPrefix  = "mcp-oauth:used-code:"
	usedLoginKeyPrefix = "mcp-oauth:used-login:"

	// refreshGrace is how long after a rotation both the token it replaced and the token it
	// produced are answered with the current one, so the requests a client sends in one burst
	// all succeed. Later, the replaced token is a replay.
	refreshGrace = 10 * time.Second
)

// errStoreUnavailable marks a failure of the grant store, as opposed to a missing grant.
// Callers answer it with 503 so clients retry instead of signing the user in again.
var errStoreUnavailable = errors.New("MCP grant store unavailable")

// grantRecord also tracks refresh token rotation: the ID of the one refresh token that
// rotates, the one it replaced, and when, for the grace window.
type grantRecord struct {
	UserID    string
	AccountID string
	ClientKey string
	Current   string
	Previous  string
	// RotatedAt is in Unix milliseconds, zero before the first rotation.
	RotatedAt int64
	// Started is when the code was redeemed, in Unix seconds.
	Started int64
}

// belongsTo reports whether a token was issued for this grant's user, account and client.
// Tokens are sealed, so a mismatch means a bug, not an attacker, and it is refused anyway.
func (r grantRecord) belongsTo(g grant) bool {
	return r.UserID == g.Identity.UserID && r.AccountID == g.Identity.AccountID && r.ClientKey == g.ClientKey
}

// GrantStore keeps the grants and the single-use markers of codes and logins. Each method
// is one atomic step, so a revocation and a rotation of the same grant cannot interleave,
// and two instances cannot rotate one refresh token two ways.
type GrantStore interface {
	// start creates the grant a code's redemption begins. When the code was redeemed before,
	// it creates nothing and returns the grant the first redemption started.
	start(ctx context.Context, codeID string, codeTTL time.Duration, grantID string, record grantRecord, ttl time.Duration) (previous string, reused bool, err error)
	// claim records the first use of a single-use key and reports whether this call was it.
	claim(ctx context.Context, key string, ttl time.Duration) (bool, error)
	// load returns the grant, or ok=false when it was revoked, has expired or never existed.
	load(ctx context.Context, grantID string) (record grantRecord, ok bool, err error)
	// rotate applies rotateGrant to the grant and returns the refresh ID to issue.
	rotate(ctx context.Context, grantID, presented, next string, now time.Time) (rotationOutcome, string, error)
	// revoke deletes the grant.
	revoke(ctx context.Context, grantID string) error
}

// NewGrantStore keeps the grants in Redis at redisURL, the address management's shared cache
// uses, or in this process when redisURL is empty, which suits a single instance only.
func NewGrantStore(ctx context.Context, redisURL string) (GrantStore, error) {
	if redisURL == "" {
		return newMemoryGrants(), nil
	}
	return newRedisGrants(ctx, redisURL)
}

type rotationOutcome int

const (
	// grantGone: the grant was revoked, has expired or never existed.
	grantGone rotationOutcome = iota
	// grantRotated: the presented refresh token was replaced by the next one.
	grantRotated
	// grantServed: the presented token is answered with the current one, without rotating.
	grantServed
	// grantReplayed: the presented token was used before. The grant is deleted.
	grantReplayed
)

// rotateGrant is the rotation rule of OAuth 2.1 section 4.3.1: only the current refresh token
// rotates, and an older one is a replay. Within refreshGrace of a rotation, the replaced and
// the new token both get the current one without rotating again, so a client's burst of
// refreshes cannot chain rotations. rotateScript is the same rule for Redis.
func rotateGrant(record *grantRecord, presented, next string, now time.Time) rotationOutcome {
	nowMs := now.UnixMilli()
	withinGrace := record.RotatedAt != 0 && nowMs-record.RotatedAt <= refreshGrace.Milliseconds()
	switch {
	case presented == record.Current && withinGrace:
		return grantServed
	case presented == record.Current:
		record.Previous, record.Current, record.RotatedAt = record.Current, next, nowMs
		return grantRotated
	case presented == record.Previous && withinGrace:
		return grantServed
	default:
		return grantReplayed
	}
}

// until turns an expiry into a store TTL, never below a second so the entry outlives the
// check that wrote it.
func (b *Broker) until(unix int64) time.Duration {
	return max(time.Unix(unix, 0).Sub(b.now()), time.Second)
}

// writeStoreError answers a token endpoint request the store could not serve.
func writeStoreError(w http.ResponseWriter, r *http.Request, err error) {
	log.WithContext(r.Context()).Errorf("MCP OAuth: %v", err)
	writeOAuthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "try again shortly")
}
