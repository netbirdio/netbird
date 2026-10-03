//go:build e2e

package reverseproxy

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/e2e/harness"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

const (
	targetAccessDomain            = "target-access." + harness.AgentNetworkCluster
	targetAccessHeader            = "X-E2E-Proxy-Key"
	targetAccessSecret            = "e2e-target-access-secret"
	targetAccessEchoPrefix        = "/e2e/proxy-echo/"
	targetAccessApplicationAuth   = "Bearer e2e-application-token"
	targetAccessApplicationCookie = "application_session=e2e-visible"
)

type targetAccessEcho struct {
	Source         string `json:"source"`
	Path           string `json:"path"`
	RequestURI     string `json:"request_uri"`
	ConfiguredAuth string `json:"configured_auth"`
	Authorization  string `json:"authorization"`
	Cookie         string `json:"cookie"`
	NetBirdUser    string `json:"netbird_user"`
	NetBirdGroups  string `json:"netbird_groups"`
}

func TestTargetAccessControl_PrivateServiceRejectsBypass(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	group, err := srv.API().Groups.Create(ctx, api.PostApiGroupsJSONRequestBody{Name: "e2e-private-target-access"})
	require.NoError(t, err, "create private-service access group")
	t.Cleanup(func() { _ = srv.API().Groups.Delete(context.Background(), group.Id) })

	request := targetAccessServiceRequest(t, "http://upstream.invalid:80",
		api.ServiceTargetAccessActionBypass,
		api.ServiceTargetAccessActionBlock,
		nil,
	)
	private := true
	accessGroups := []string{group.Id}
	request.Domain = "private-target-access." + harness.AgentNetworkCluster
	request.Name = "E2E private target access rejection"
	request.Private = &private
	request.AccessGroups = &accessGroups

	created, err := srv.API().ReverseProxyServices.Create(ctx, request)
	if created != nil {
		t.Cleanup(func() { _ = srv.API().ReverseProxyServices.Delete(context.Background(), created.Id) })
	}
	assert.Nil(t, created)
	assert.ErrorContains(t, err, "bypass access_action is not supported for private services")
}

func TestTargetAccessControl_PublicServiceLifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()

	upstream, err := harness.StartHTTPUpstream(ctx, srv)
	require.NoError(t, err, "start HTTP upstream")
	t.Cleanup(func() { _ = upstream.Terminate(context.Background()) })

	proxyToken, err := srv.CreateProxyTokenCLI(ctx, "e2e-target-access-proxy")
	require.NoError(t, err, "mint global proxy token")
	px, err := harness.StartProxy(ctx, srv, proxyToken, map[string]string{"NB_PROXY_PRIVATE": "false"})
	require.NoError(t, err, "start public reverse proxy")
	t.Cleanup(func() { _ = px.Terminate(context.Background()) })

	request := targetAccessServiceRequest(t, upstream.URL,
		api.ServiceTargetAccessActionBypass,
		api.ServiceTargetAccessActionBlock,
		nil,
	)
	created, err := srv.API().ReverseProxyServices.Create(ctx, request)
	require.NoError(t, err, "create service with per-target access actions")
	removed := false
	t.Cleanup(func() {
		if !removed {
			_ = srv.API().ReverseProxyServices.Delete(context.Background(), created.Id)
		}
	})

	validAuth := targetAccessForwardedHeaders(targetAccessSecret)
	wrongAuth := http.Header{targetAccessHeader: []string{"wrong-secret"}}
	spoofedBypass := targetAccessForwardedHeaders("wrong-secret")

	// Wait for the service snapshot before issuing unique one-shot markers. A
	// marker used while polling could reach an older mapping and make an updated
	// block look as though it forwarded after convergence.
	requireProxyStatus(t, ctx, px, targetAccessPath("", "warm-created"), nil,
		http.StatusUnauthorized, "wait for created service")
	requireProxyAttempt(t, ctx, px, upstream, "", "inherit-missing", nil,
		http.StatusUnauthorized, 0, "inherit target without service credentials")
	requireProxyAttempt(t, ctx, px, upstream, "", "inherit-wrong", wrongAuth,
		http.StatusUnauthorized, 0, "inherit target with invalid service credentials")
	requireProxyEcho(t, ctx, px, upstream, "", "inherit-valid", validAuth,
		"inherit target with valid service credentials")
	requireProxyEcho(t, ctx, px, upstream, "/public", "bypass-initial", spoofedBypass,
		"bypass target without valid service credentials")
	requireProxyAttempt(t, ctx, px, upstream, "/public/private", "nested-missing", nil,
		http.StatusUnauthorized, 0, "nested inherit target overrides bypass parent")
	requireProxyEcho(t, ctx, px, upstream, "/public/private", "nested-valid", validAuth,
		"nested inherit target accepts valid service credentials")
	requireProxyAttempt(t, ctx, px, upstream, "/blocked", "block-initial", validAuth,
		http.StatusForbidden, 0, "block target even with valid service credentials")

	request = targetAccessServiceRequest(t, upstream.URL,
		api.ServiceTargetAccessActionBlock,
		api.ServiceTargetAccessActionBypass,
		nil,
	)
	_, err = srv.API().ReverseProxyServices.Update(ctx, created.Id, request)
	require.NoError(t, err, "swap target access actions")
	requireProxyStatus(t, ctx, px, targetAccessPath("/public", "warm-actions-updated"), validAuth,
		http.StatusForbidden, "wait for target action update")
	requireProxyAttempt(t, ctx, px, upstream, "/public", "public-updated-block", validAuth,
		http.StatusForbidden, 0, "updated public target is blocked")
	requireProxyEcho(t, ctx, px, upstream, "/blocked", "blocked-updated-bypass", spoofedBypass,
		"updated blocked target bypasses authentication")

	blockedCIDRs := []string{"0.0.0.0/0", "::/0"}
	request = targetAccessServiceRequest(t, upstream.URL,
		api.ServiceTargetAccessActionBlock,
		api.ServiceTargetAccessActionBypass,
		&api.AccessRestrictions{BlockedCidrs: &blockedCIDRs},
	)
	_, err = srv.API().ReverseProxyServices.Update(ctx, created.Id, request)
	require.NoError(t, err, "add connection restriction")
	requireProxyStatus(t, ctx, px, targetAccessPath("/blocked", "warm-restricted"), nil,
		http.StatusForbidden, "wait for connection restriction")
	requireProxyAttempt(t, ctx, px, upstream, "/blocked", "blocked-restricted", spoofedBypass,
		http.StatusForbidden, 0, "connection restriction runs before bypass")

	// Clear the restriction and prove the route is live immediately before
	// deleting it, so a stale 403 cannot make the removal check pass.
	request = targetAccessServiceRequest(t, upstream.URL,
		api.ServiceTargetAccessActionBlock,
		api.ServiceTargetAccessActionBypass,
		&api.AccessRestrictions{},
	)
	_, err = srv.API().ReverseProxyServices.Update(ctx, created.Id, request)
	require.NoError(t, err, "clear connection restriction")
	requireProxyStatus(t, ctx, px, targetAccessPath("/blocked", "warm-restriction-cleared"), nil,
		http.StatusOK, "wait for cleared connection restriction")
	requireProxyEcho(t, ctx, px, upstream, "/blocked", "blocked-restriction-cleared", spoofedBypass,
		"bypass route is live before removal")

	require.NoError(t, srv.API().ReverseProxyServices.Delete(ctx, created.Id), "delete service")
	removed = true
	requireProxyStatus(t, ctx, px, targetAccessPath("/blocked", "warm-deleted"), nil,
		http.StatusNotFound, "wait for service deletion")
	requireProxyAttempt(t, ctx, px, upstream, "/blocked", "blocked-deleted", nil,
		http.StatusNotFound, 0, "deleted service is removed from the proxy")
}

func targetAccessServiceRequest(
	t *testing.T,
	upstreamURL string,
	publicAction, blockedAction api.ServiceTargetAccessAction,
	restrictions *api.AccessRestrictions,
) api.ServiceRequest {
	t.Helper()

	u, err := url.Parse(upstreamURL)
	require.NoError(t, err)
	host, portText, err := net.SplitHostPort(u.Host)
	require.NoError(t, err)
	port, err := strconv.Atoi(portText)
	require.NoError(t, err)

	rootPath := "/"
	publicPath := "/public"
	nestedPath := "/public/private"
	blockedPath := "/blocked"
	directUpstream := true
	mode := api.ServiceRequestModeHttp
	private := false
	inherit := api.ServiceTargetAccessActionInherit

	target := func(path *string, action *api.ServiceTargetAccessAction) api.ServiceTarget {
		return api.ServiceTarget{
			AccessAction: action,
			Enabled:      true,
			Host:         &host,
			Options:      &api.ServiceTargetOptions{DirectUpstream: &directUpstream},
			Path:         path,
			Port:         port,
			Protocol:     api.ServiceTargetProtocolHttp,
			TargetId:     harness.AgentNetworkCluster,
			TargetType:   api.ServiceTargetTargetTypeCluster,
		}
	}
	targets := []api.ServiceTarget{
		target(&rootPath, &inherit),
		target(&publicPath, &publicAction),
		target(&nestedPath, &inherit),
		target(&blockedPath, &blockedAction),
	}
	headerAuths := []api.HeaderAuthConfig{{
		Enabled: true,
		Header:  targetAccessHeader,
		Value:   targetAccessSecret,
	}}

	return api.ServiceRequest{
		AccessRestrictions: restrictions,
		Auth:               &api.ServiceAuthConfig{HeaderAuths: &headerAuths},
		Domain:             targetAccessDomain,
		Enabled:            true,
		Mode:               &mode,
		Name:               "E2E target access control",
		Private:            &private,
		Targets:            &targets,
	}
}

func targetAccessForwardedHeaders(authValue string) http.Header {
	return http.Header{
		targetAccessHeader: []string{authValue},
		"Authorization":    []string{targetAccessApplicationAuth},
		"Cookie":           []string{"nb_session=e2e-proxy-session; " + targetAccessApplicationCookie},
		"X-NetBird-User":   []string{"spoofed@example.com"},
		"X-NetBird-Groups": []string{"administrators"},
	}
}

func targetAccessPath(targetPrefix, marker string) string {
	return targetPrefix + targetAccessEchoPrefix + marker
}

func requireProxyAttempt(
	t *testing.T,
	ctx context.Context,
	px *harness.Proxy,
	upstream *harness.HTTPUpstream,
	targetPrefix, marker string,
	headers http.Header,
	wantStatus, wantUpstreamRequests int,
	description string,
) string {
	t.Helper()

	path := targetAccessPath(targetPrefix, marker)
	status, body, requestErr := px.HTTPSGet(ctx, targetAccessDomain, path, headers)
	syncErr := upstream.Synchronize(ctx)
	count, countErr := upstream.RequestCount(ctx, marker)
	if requestErr != nil || syncErr != nil || countErr != nil || status != wantStatus || count != wantUpstreamRequests {
		t.Fatalf("%s: wanted status=%d upstream_requests=%d, got status=%d upstream_requests=%d body=%q request_error=%v sync_error=%v count_error=%v\n=== proxy logs ===\n%s\n=== upstream logs ===\n%s",
			description, wantStatus, wantUpstreamRequests, status, count, body, requestErr, syncErr, countErr,
			px.Logs(context.Background()), upstream.Logs(context.Background()))
	}
	return body
}

func requireProxyEcho(
	t *testing.T,
	ctx context.Context,
	px *harness.Proxy,
	upstream *harness.HTTPUpstream,
	targetPrefix, marker string,
	headers http.Header,
	description string,
) {
	t.Helper()

	body := requireProxyAttempt(t, ctx, px, upstream, targetPrefix, marker, headers,
		http.StatusOK, 1, description)
	var echo targetAccessEcho
	require.NoError(t, json.Unmarshal([]byte(body), &echo), "decode HTTP upstream observation")
	wantPath := targetAccessEchoPrefix + marker
	assert.Equal(t, "netbird-e2e-http-upstream", echo.Source, "response must come from the test upstream")
	assert.Equal(t, wantPath, echo.Path, "upstream must receive the routed subpath")
	assert.Equal(t, wantPath, echo.RequestURI, "upstream request URI must not contain the matched target prefix")
	assert.Empty(t, echo.ConfiguredAuth, "configured proxy authentication header must be stripped")
	assert.Equal(t, targetAccessApplicationAuth, echo.Authorization, "application authorization must be preserved")
	assert.NotContains(t, echo.Cookie, "nb_session=", "proxy session cookie must be stripped")
	assert.Contains(t, echo.Cookie, targetAccessApplicationCookie, "application cookie must be preserved")
	assert.Empty(t, echo.NetBirdUser, "client-supplied NetBird identity must be stripped")
	assert.Empty(t, echo.NetBirdGroups, "client-supplied NetBird groups must be stripped")
}

func requireProxyStatus(
	t *testing.T,
	ctx context.Context,
	px *harness.Proxy,
	path string,
	headers http.Header,
	want int,
	description string,
) {
	t.Helper()

	deadline := time.Now().Add(90 * time.Second)
	var lastCode int
	var lastBody string
	var lastErr error
	for time.Now().Before(deadline) {
		lastCode, lastBody, lastErr = px.HTTPSGet(ctx, targetAccessDomain, path, headers)
		if lastErr == nil && lastCode == want {
			return
		}
		if !waitBeforeRetry(ctx, time.Second) {
			break
		}
	}
	t.Fatalf("%s: wanted status %d, last status=%d body=%q error=%v\n=== proxy logs ===\n%s",
		description, want, lastCode, lastBody, lastErr, px.Logs(context.Background()))
}

func waitBeforeRetry(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
