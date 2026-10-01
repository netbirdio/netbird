//go:build e2e

package reverseproxy

import (
	"context"
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
	targetAccessDomain = "target-access." + harness.AgentNetworkCluster
	targetAccessHeader = "X-E2E-Proxy-Key"
	targetAccessSecret = "e2e-target-access-secret"
)

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

	upstream, err := harness.StartVLLM(ctx, srv)
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

	validAuth := http.Header{targetAccessHeader: []string{targetAccessSecret}}
	spoofedBypass := http.Header{
		targetAccessHeader: []string{"wrong-secret"},
		"X-NetBird-User":   []string{"spoofed@example.com"},
		"X-NetBird-Groups": []string{"administrators"},
	}

	requireProxyStatus(t, ctx, px, "/private", nil, http.StatusUnauthorized,
		"inherit target without service credentials")
	requireProxyStatus(t, ctx, px, "/private", validAuth, http.StatusOK,
		"inherit target with valid service credentials")
	requireProxyStatus(t, ctx, px, "/public/ready", spoofedBypass, http.StatusOK,
		"bypass target without valid service credentials")
	requireProxyStatus(t, ctx, px, "/blocked/secret", validAuth, http.StatusForbidden,
		"block target even with valid service credentials")

	request = targetAccessServiceRequest(t, upstream.URL,
		api.ServiceTargetAccessActionBlock,
		api.ServiceTargetAccessActionBypass,
		nil,
	)
	_, err = srv.API().ReverseProxyServices.Update(ctx, created.Id, request)
	require.NoError(t, err, "swap target access actions")
	requireProxyStatus(t, ctx, px, "/public/ready", validAuth, http.StatusForbidden,
		"updated public target is blocked")
	requireProxyStatus(t, ctx, px, "/blocked/ready", nil, http.StatusOK,
		"updated blocked target bypasses authentication")

	blockedCIDRs := []string{"0.0.0.0/0", "::/0"}
	request = targetAccessServiceRequest(t, upstream.URL,
		api.ServiceTargetAccessActionBlock,
		api.ServiceTargetAccessActionBypass,
		&api.AccessRestrictions{BlockedCidrs: &blockedCIDRs},
	)
	_, err = srv.API().ReverseProxyServices.Update(ctx, created.Id, request)
	require.NoError(t, err, "add connection restriction")
	requireProxyStatus(t, ctx, px, "/blocked/ready", nil, http.StatusForbidden,
		"connection restriction runs before bypass")

	// Clear the restriction and prove the route is live immediately before
	// deleting it, so a stale 403 cannot make the removal check pass.
	request = targetAccessServiceRequest(t, upstream.URL,
		api.ServiceTargetAccessActionBlock,
		api.ServiceTargetAccessActionBypass,
		&api.AccessRestrictions{},
	)
	_, err = srv.API().ReverseProxyServices.Update(ctx, created.Id, request)
	require.NoError(t, err, "clear connection restriction")
	requireProxyStatus(t, ctx, px, "/blocked/ready", nil, http.StatusOK,
		"bypass route is live before removal")

	require.NoError(t, srv.API().ReverseProxyServices.Delete(ctx, created.Id), "delete service")
	removed = true
	requireProxyStatus(t, ctx, px, "/blocked/ready", nil, http.StatusNotFound,
		"deleted service is removed from the proxy")
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
