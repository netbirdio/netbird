package auth

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
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

// agentNetworkResolver routes every path to an agent-network target whose
// account has log collection off, the way the agent-network synthesizer does.
// Matching a request to it marks the request as agent-network.
func agentNetworkResolver(t *testing.T) *proxy.TargetResolver {
	t.Helper()
	targetURL, err := url.Parse("https://api.anthropic.com")
	require.NoError(t, err)
	resolver, err := proxy.NewTargetResolver(proxy.Mapping{
		ID:        "svc-1",
		AccountID: "acct-1",
		Host:      testServerHost,
		Paths: map[string]*proxy.PathTarget{
			"/": {URL: targetURL, AgentNetwork: true, DisableAccessLog: true},
		},
	})
	require.NoError(t, err)
	return resolver
}

// TestPrivateDenyLeavesAgentNetworkLog covers a caller the private gateway
// refuses after matching it to an agent-network target, such as a client that
// is not connected to NetBird. The 403 is the proxy's own, and the request goes
// to the regular reverse-proxy log rather than an agent-network row with no
// user, provider or model. The account's agent-network log collection setting
// does not hide it, since the caller was never identified as one of its users.
func TestPrivateDenyLeavesAgentNetworkLog(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	require.NoError(t, mw.AddDomain(testServerHost, nil, "", 0, "acct-1", "svc-1", nil, true, nil, WithTargetResolver(agentNetworkResolver(t))))

	rec, cd := serveProtected(t, mw, testTunnelIP, "")

	assert.Equal(t, http.StatusForbidden, rec.Code, "an unvalidated tunnel peer must be refused")
	assert.Equal(t, proxy.OriginAuth, cd.GetOrigin(), "the proxy's own refusal is an auth rejection")
	assert.False(t, cd.GetAgentNetwork(), "a refused caller goes to the reverse-proxy log, not the agent-network log")
	assert.False(t, cd.GetSuppressAccessLog(), "the agent-network log collection setting does not apply to a refused caller")
}

// TestIPRestrictionDenyIsNotAgentNetwork covers a denial that happens before
// the request is matched to a target. It was never agent-network traffic and
// stays in the reverse-proxy log, as it always has.
func TestIPRestrictionDenyIsNotAgentNetwork(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	filter := restrict.ParseFilter(restrict.FilterConfig{AllowedCIDRs: []string{"10.0.0.0/8"}})
	require.NoError(t, mw.AddDomain(testServerHost, nil, "", 0, "acct-1", "svc-1", filter, false, nil, WithTargetResolver(agentNetworkResolver(t))))

	rec, cd := serveProtected(t, mw, netip.MustParseAddr("192.0.2.10"), "")

	assert.Equal(t, http.StatusForbidden, rec.Code, "an address outside the allowlist must be refused")
	assert.Equal(t, proxy.OriginAuth, cd.GetOrigin(), "an IP-restriction refusal is an auth rejection")
	assert.False(t, cd.GetAgentNetwork(), "a refusal before target matching is not agent-network traffic")
	assert.False(t, cd.GetSuppressAccessLog(), "a refusal before target matching is logged regardless of log collection")
}

// TestCrossAccountDenyIsNotAgentNetwork covers a request that arrived through
// another account's tunnel. Its access log is written under the caller's
// account, so it must not appear in that account's agent-network log as a
// request to a gateway it does not own.
func TestCrossAccountDenyIsNotAgentNetwork(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	require.NoError(t, mw.AddDomain(testServerHost, nil, "", 0, "acct-1", "svc-1", nil, true, nil, WithTargetResolver(agentNetworkResolver(t))))

	rec, cd := serveProtected(t, mw, testTunnelIP, "acct-other")

	assert.Equal(t, http.StatusForbidden, rec.Code, "a request from another account must be refused")
	assert.Equal(t, proxy.OriginAuth, cd.GetOrigin(), "the refusal is still the proxy's")
	assert.False(t, cd.GetAgentNetwork(), "another account's request is not this gateway's agent-network traffic")
}
