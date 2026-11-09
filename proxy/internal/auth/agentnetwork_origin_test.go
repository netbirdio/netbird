package auth

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/proxy/internal/proxy"
	"github.com/netbirdio/netbird/proxy/internal/restrict"
	"github.com/netbirdio/netbird/proxy/internal/types"
)

// serveProtected runs one request through Protect and returns the captured
// data the access log would read, so a test can check how the rejection is
// attributed.
func serveProtected(t *testing.T, mw *Middleware, clientIP netip.Addr, callerAccount types.AccountID) (*httptest.ResponseRecorder, *proxy.CapturedData) {
	t.Helper()
	cd := proxy.NewCapturedData("")
	cd.SetClientIP(clientIP)
	if callerAccount != "" {
		cd.SetAccountID(callerAccount)
	}
	req := httptest.NewRequest(http.MethodGet, "http://"+testServerHost+"/v1/chat/completions", nil)
	req = req.WithContext(proxy.WithCapturedData(req.Context(), cd))
	rec := httptest.NewRecorder()
	mw.Protect(newPassthroughHandler()).ServeHTTP(rec, req)
	return rec, cd
}

// TestPrivateDenyIsAttributedToAuth covers a peer the private gateway refuses:
// before, denyPrivate set no origin and the access log reported the proxy's
// own 403 as the provider's.
func TestPrivateDenyIsAttributedToAuth(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	require.NoError(t, mw.AddDomain(testServerHost, nil, "", 0, "acct-1", "svc-1", nil, true, nil, WithAgentNetwork(true, false)))

	rec, cd := serveProtected(t, mw, testTunnelIP, "")

	assert.Equal(t, http.StatusForbidden, rec.Code, "an unvalidated tunnel peer must be refused")
	assert.Equal(t, proxy.OriginAuth, cd.GetOrigin(), "the proxy's own refusal is an auth rejection")
	assert.True(t, cd.GetAgentNetwork(), "the rejection is logged as an agent-network request")
}

// TestIPRestrictionDenyIsAgentNetwork covers a denial that happens before the
// request is matched to a target: the domain's flags still classify it, and
// the access-log suppression of the account carries over.
func TestIPRestrictionDenyIsAgentNetwork(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	filter := restrict.ParseFilter(restrict.FilterConfig{AllowedCIDRs: []string{"10.0.0.0/8"}})
	require.NoError(t, mw.AddDomain(testServerHost, nil, "", 0, "acct-1", "svc-1", filter, false, nil, WithAgentNetwork(true, true)))

	rec, cd := serveProtected(t, mw, netip.MustParseAddr("192.0.2.10"), "")

	assert.Equal(t, http.StatusForbidden, rec.Code, "an address outside the allowlist must be refused")
	assert.Equal(t, proxy.OriginAuth, cd.GetOrigin(), "an IP-restriction refusal is an auth rejection")
	assert.True(t, cd.GetAgentNetwork(), "the rejection is logged as an agent-network request")
	assert.True(t, cd.GetSuppressAccessLog(), "an account with log collection off keeps it off for rejections")
}

// TestCrossAccountDenyIsNotAgentNetwork covers a request that arrived through
// another account's tunnel. Its access log is written under the caller's
// account, so it must not appear in that account's agent-network log as a
// request to a gateway it does not own.
func TestCrossAccountDenyIsNotAgentNetwork(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	require.NoError(t, mw.AddDomain(testServerHost, nil, "", 0, "acct-1", "svc-1", nil, true, nil, WithAgentNetwork(true, false)))

	rec, cd := serveProtected(t, mw, testTunnelIP, "acct-other")

	assert.Equal(t, http.StatusForbidden, rec.Code, "a request from another account must be refused")
	assert.Equal(t, proxy.OriginAuth, cd.GetOrigin(), "the refusal is still the proxy's")
	assert.False(t, cd.GetAgentNetwork(), "another account's request is not this gateway's agent-network traffic")
}
