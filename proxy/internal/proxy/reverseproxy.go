package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/proxy/auth"
	"github.com/netbirdio/netbird/proxy/internal/middleware"
	"github.com/netbirdio/netbird/proxy/internal/middleware/bodytap"
	"github.com/netbirdio/netbird/proxy/internal/roundtrip"
	"github.com/netbirdio/netbird/proxy/internal/types"
	"github.com/netbirdio/netbird/proxy/web"
	"github.com/netbirdio/netbird/trustedproxy"
)

type ReverseProxy struct {
	transport http.RoundTripper
	// forwardedProto overrides the X-Forwarded-Proto header value.
	// Valid values: "auto" (detect from TLS), "http", "https".
	forwardedProto string
	// trustedProxies is the set of trusted upstream proxies. When the direct
	// connection comes from a trusted proxy, forwarding headers are preserved
	// and appended to instead of being stripped.
	trustedProxies *trustedproxy.List
	mappingsMux    sync.RWMutex
	mappings       map[string]Mapping
	logger         *log.Logger
	// middlewareManager, when non-nil, drives per-target middleware
	// dispatch. A nil manager (or an empty chain for the resolved
	// target) keeps the reverse-proxy hot path on the no-capture fast
	// path with no middleware overhead.
	middlewareManager *middleware.Manager
}

// Option configures optional ReverseProxy behavior. Options exist so the core
// constructor signature stays stable across additive features.
type Option func(*ReverseProxy)

// WithMiddlewareManager attaches a middleware manager to the reverse
// proxy. When the manager is nil or returns an empty chain for the
// target, the request follows the fast path with no middleware
// overhead.
func WithMiddlewareManager(m *middleware.Manager) Option {
	return func(p *ReverseProxy) {
		p.middlewareManager = m
	}
}

// NewReverseProxy configures a new NetBird ReverseProxy.
// This is a wrapper around an httputil.ReverseProxy set
// to dynamically route requests based on internal mapping
// between requested URLs and targets.
// The internal mappings can be modified using the AddMapping
// and RemoveMapping functions.
func NewReverseProxy(transport http.RoundTripper, forwardedProto string, trustedProxies *trustedproxy.List, logger *log.Logger, opts ...Option) *ReverseProxy {
	if logger == nil {
		logger = log.StandardLogger()
	}
	p := &ReverseProxy{
		transport:      transport,
		forwardedProto: forwardedProto,
		trustedProxies: trustedProxies,
		mappings:       make(map[string]Mapping),
		logger:         logger,
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

func (p *ReverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	result, exists := p.findTargetForRequest(r)
	if !exists {
		p.serveRouteError(w, r, http.StatusNotFound, "Service Not Found",
			"The requested service could not be found. Please check the URL, try refreshing, or check if the peer is running. If that doesn't work, see our documentation for help.")
		return
	}

	// Loop guard for private services: a peer that hosts the target
	// dialing its own service URL would round-trip its own traffic
	// through the proxy and back over WG to itself. Refuse the request
	// with 421 (Misdirected Request) so the caller sees an explicit
	// error instead of silently doubling tunnel traffic.
	if p.isSelfTargetLoop(r, result.target.URL) {
		p.serveRouteError(w, r, http.StatusMisdirectedRequest, "Loop Detected",
			"This peer is the target of the requested service. Reach the backend directly instead of dialing the public service URL from the same machine.")
		return
	}

	pt := result.target
	ctx := p.buildTargetContext(r.Context(), result)

	// Populate captured data if it exists (allows middleware to read after handler completes).
	// This solves the problem of passing data UP the middleware chain: we put a mutable struct
	// pointer in the context, and mutate the struct here so outer middleware can read it.
	capturedData := CapturedDataFromContext(ctx)
	if capturedData != nil {
		capturedData.SetServiceID(result.serviceID)
		capturedData.SetAccountID(result.accountID)
		capturedData.SetAgentNetwork(result.target != nil && result.target.AgentNetwork)
		capturedData.SetSuppressAccessLog(result.target != nil && result.target.DisableAccessLog)
	}

	rewriteMatchedPath := result.matchedPath
	if pt.PathRewrite == PathRewritePreserve {
		rewriteMatchedPath = ""
	}

	chain := p.resolveChain(result)
	if chain == nil || chain.Empty() {
		p.serveDirect(w, r, ctx, result, rewriteMatchedPath)
		return
	}
	p.serveWithChain(w, r, ctx, result, chain, rewriteMatchedPath, capturedData)
}

// serveRouteError marks the request as un-routed on any captured-data
// context and renders the proxy error page.
func (p *ReverseProxy) serveRouteError(w http.ResponseWriter, r *http.Request, status int, title, message string) {
	if cd := CapturedDataFromContext(r.Context()); cd != nil {
		cd.SetOrigin(OriginNoRoute)
	}
	web.ServeErrorPage(w, r, status, title, message, getRequestID(r),
		web.ErrorStatus{Proxy: true, Destination: false})
}

// buildTargetContext layers the per-target roundtrip flags (account id,
// TLS-verify skip, direct upstream, dial timeout) onto the request context.
func (p *ReverseProxy) buildTargetContext(ctx context.Context, result targetResult) context.Context {
	pt := result.target
	ctx = roundtrip.WithAccountID(ctx, result.accountID)
	if pt.SkipTLSVerify {
		ctx = roundtrip.WithSkipTLSVerify(ctx)
	}
	if pt.DirectUpstream {
		ctx = roundtrip.WithDirectUpstream(ctx)
	}
	if pt.RequestTimeout > 0 {
		ctx = types.WithDialTimeout(ctx, pt.RequestTimeout)
	}
	return ctx
}

// serveDirect forwards the request without a middleware chain — the common
// path for plain reverse-proxy targets.
func (p *ReverseProxy) serveDirect(w http.ResponseWriter, r *http.Request, ctx context.Context, result targetResult, rewriteMatchedPath string) {
	pt := result.target
	rp := &httputil.ReverseProxy{
		Rewrite:       p.rewriteFunc(pt.URL, rewriteMatchedPath, result.passHostHeader, pt.PathRewrite, pt.CustomHeaders, result.stripAuthHeaders),
		Transport:     p.transport,
		FlushInterval: -1,
		ErrorHandler:  p.proxyErrorHandler,
	}
	if result.rewriteRedirects {
		rp.ModifyResponse = p.rewriteLocationFunc(pt.URL, rewriteMatchedPath, r) //nolint:bodyclose
	}
	rp.ServeHTTP(w, r.WithContext(ctx))
}

// serveWithChain runs the per-target middleware chain around the upstream
// request: request-leg capture and authorisation, then (on allow) the
// upstream forward with response/terminal observation deferred so it reads
// the captured response before the writer is released.
func (p *ReverseProxy) serveWithChain(w http.ResponseWriter, r *http.Request, ctx context.Context, result targetResult, chain *middleware.Chain, rewriteMatchedPath string, capturedData *CapturedData) {
	middlewareIDs := chain.IDs()
	p.logger.Debugf("middleware chain matched: service=%s path=%s middlewares=%v", result.serviceID, result.matchedPath, middlewareIDs)

	capturedBody, truncated, originalSize, releaseBudget := p.captureRequestForChain(ctx, r, result, capturedData)
	defer releaseBudget()

	acc := middleware.NewAccumulator(middleware.MaxRequestMetadataBytes)
	reqInput := buildRequestInput(r, result, capturedData, capturedBody, truncated, originalSize)

	denyOutput, requestMeta, upstreamRewrite, _ := chain.RunRequest(ctx, r, reqInput, acc)
	if capturedData != nil {
		for _, kv := range requestMeta {
			capturedData.SetMetadata(kv.Key, kv.Value)
		}
	}
	if denyOutput != nil {
		p.serveDeny(w, denyOutput, result, middlewareIDs)
		return
	}

	respWriter, capturingWriter := p.newResponseWriter(ctx, w, result, capturedData)
	if capturingWriter != nil {
		defer capturingWriter.Release()
		defer p.observeResponse(ctx, chain, acc, reqInput, requestMeta, capturingWriter, w, capturedData, result, middlewareIDs)
	}

	p.forwardUpstream(respWriter, r, ctx, result, rewriteMatchedPath, upstreamRewrite)
}

// captureRequestForChain copies the request body for inspection by the
// chain, records any capture bypass, and applies agent-network routing
// recovery for oversized bodies. The returned release frees the capture
// budget and must be deferred by the caller.
func (p *ReverseProxy) captureRequestForChain(ctx context.Context, r *http.Request, result targetResult, capturedData *CapturedData) ([]byte, bool, int64, func()) {
	pt := result.target
	capturedBody, truncated, originalSize, bypass, releaseBudget, captureErr := bodytap.CaptureRequest(r, pt.CaptureConfig, p.middlewareManager.Budget())
	if captureErr != nil {
		p.logger.Debugf("middleware request body capture error: %v", captureErr)
	}
	if bypass != "" {
		if capturedData != nil {
			capturedData.SetMetadata("mw.capture.bypass_reason", bypass)
		}
		p.middlewareManager.Metrics().IncCaptureBypass(ctx, string(result.serviceID), bypass)
	}

	// Routing recovery for oversized agent-network requests: when the body
	// exceeded the capture cap (bypassed or truncated), the captured copy
	// can't be parsed for the model, so llm_router would deny with
	// model_not_routable. Scan the full stream for just the routing fields
	// and hand the request parser a minimal stub so routing succeeds; the
	// prompt stays uncaptured and the upstream still gets the full body.
	if pt.AgentNetwork && (truncated || capturedBody == nil) {
		if model, stream, ok := bodytap.ScanRoutingFields(r, bodytap.MaxRoutingScanBytes); ok {
			capturedBody = buildRoutingStub(model, stream)
			truncated = false
			p.logger.Debugf("agent-network routing recovery: extracted model=%s stream=%t from oversized request body (service=%s)", model, stream, result.serviceID)
		}
	}
	return capturedBody, truncated, originalSize, releaseBudget
}

// serveDeny renders the chain's deny response. Policy/budget/routing/guardrail
// denials are expected runtime outcomes and can be high-volume under
// misconfigured or hostile clients; per-request detail stays at Debug and
// metrics/access logs carry the signal at scale.
func (p *ReverseProxy) serveDeny(w http.ResponseWriter, denyOutput *middleware.Output, result targetResult, middlewareIDs []string) {
	middlewareID := "middleware"
	if denyOutput.DenyReason != nil && denyOutput.DenyReason.Code != "" {
		middlewareID = denyOutput.DenyReason.Code
	}
	p.logger.Debugf("middleware chain denied request: service=%s path=%s middlewares=%v reason=%s status=%d",
		result.serviceID, result.matchedPath, middlewareIDs, middlewareID, denyOutput.DenyStatus)
	middleware.RenderDenyResponse(w, middlewareID, denyOutput.DenyReason, denyOutput.DenyStatus)
}

// newResponseWriter returns the writer the upstream forward should use. When
// response capture is enabled and not bypassed it wraps w in a capturing
// writer (also returned so the caller can release it and feed the response
// leg); otherwise the capturing writer is nil and w is used directly.
func (p *ReverseProxy) newResponseWriter(ctx context.Context, w http.ResponseWriter, result targetResult, capturedData *CapturedData) (http.ResponseWriter, *bodytap.CapturingResponseWriter) {
	pt := result.target
	if pt.CaptureConfig == nil || pt.CaptureConfig.MaxResponseBytes <= 0 {
		return w, nil
	}
	capturingWriter := bodytap.NewCapturingResponseWriter(w, pt.CaptureConfig.MaxResponseBytes, p.middlewareManager.Budget())
	if capturingWriter.Bypassed() {
		if capturedData != nil {
			capturedData.SetMetadata("mw.capture.bypass_reason", capturingWriter.BypassReason())
		}
		p.middlewareManager.Metrics().IncCaptureBypass(ctx, string(result.serviceID), capturingWriter.BypassReason())
		capturingWriter.Release()
		return w, nil
	}
	return capturingWriter, capturingWriter
}

// observeResponse runs the response and terminal middleware slots after the
// body has been forwarded. It is deferred by serveWithChain so it reads the
// captured response before the writer is released.
func (p *ReverseProxy) observeResponse(ctx context.Context, chain *middleware.Chain, acc *middleware.Accumulator, reqInput *middleware.Input, requestMeta []middleware.KV, capturingWriter *bodytap.CapturingResponseWriter, w http.ResponseWriter, capturedData *CapturedData, result targetResult, middlewareIDs []string) {
	respInput := &middleware.Input{
		Slot:              middleware.SlotOnResponse,
		RequestID:         reqInput.RequestID,
		TargetID:          reqInput.TargetID,
		Method:            reqInput.Method,
		URL:               reqInput.URL,
		Headers:           reqInput.Headers,
		Status:            capturingWriter.Status(),
		RespHeaders:       headerToKV(w.Header()),
		RespBody:          capturingWriter.Body(),
		RespBodyTruncated: capturingWriter.Truncated(),
		OriginalRespSize:  capturingWriter.BytesWritten(),
		ServiceID:         reqInput.ServiceID,
		AccountID:         reqInput.AccountID,
		UserID:            reqInput.UserID,
		// UserEmail / UserGroups / UserGroupNames must flow into the
		// response leg too — llm_limit_record needs UserGroups to send
		// group_ids on RecordLLMUsage so management's account-budget
		// fan-out can match group-targeted rules; identity-stamping and
		// any future response-side authorisation also depend on these.
		UserEmail:      reqInput.UserEmail,
		UserGroups:     reqInput.UserGroups,
		UserGroupNames: reqInput.UserGroupNames,
		AuthMethod:     reqInput.AuthMethod,
		SourceIP:       reqInput.SourceIP,
		Metadata:       requestMeta,
		AgentNetwork:   reqInput.AgentNetwork,
	}
	// The response/terminal phase runs after the body is forwarded, so
	// a streaming client (e.g. Codex) has usually disconnected by now,
	// cancelling r.Context(). These middlewares only observe and record
	// (token/cost metering, usage recording) and must still complete —
	// otherwise the dispatcher short-circuits each to fail-mode and the
	// usage is silently lost. Detach from client cancellation, keep ctx
	// values, and bound the work.
	obsCtx, obsCancel := context.WithTimeout(context.WithoutCancel(ctx), observabilityPhaseTimeout)
	defer obsCancel()

	respMeta := chain.RunResponse(obsCtx, respInput, acc)
	if capturedData != nil {
		for _, kv := range respMeta {
			capturedData.SetMetadata(kv.Key, kv.Value)
		}
	}

	// Terminal slot sees the merged metadata bag from request and
	// response phases.
	mergedMeta := append(append([]middleware.KV(nil), requestMeta...), respMeta...)
	termInput := *respInput
	termInput.Slot = middleware.SlotTerminal
	termInput.Metadata = mergedMeta
	termMeta := chain.RunTerminal(obsCtx, &termInput, acc)
	if capturedData != nil {
		for _, kv := range termMeta {
			capturedData.SetMetadata(kv.Key, kv.Value)
		}
	}

	p.logger.Debugf("middleware chain ran: service=%s path=%s middlewares=%v status=%d req_meta=%d resp_meta=%d term_meta=%d",
		result.serviceID, result.matchedPath, middlewareIDs, capturingWriter.Status(), len(requestMeta), len(respMeta), len(termMeta))
}

// forwardUpstream applies any middleware-emitted upstream rewrite and proxies
// the request to the effective upstream URL.
func (p *ReverseProxy) forwardUpstream(respWriter http.ResponseWriter, r *http.Request, ctx context.Context, result targetResult, rewriteMatchedPath string, upstreamRewrite *middleware.UpstreamRewrite) {
	pt := result.target
	effectiveURL := applyUpstreamRewrite(pt.URL, upstreamRewrite)
	if upstreamRewrite != nil {
		r.Host = effectiveURL.Host
		applyUpstreamHeaders(r, upstreamRewrite)
		stripUpstreamPathPrefix(r, upstreamRewrite.StripPathPrefix)
		// A router-selected route (e.g. agent-network provider) can opt into
		// skipping upstream TLS verification per its provider config.
		if upstreamRewrite.SkipTLSVerify {
			ctx = roundtrip.WithSkipTLSVerify(ctx)
		}
	}

	rp := &httputil.ReverseProxy{
		Rewrite:       p.rewriteFunc(effectiveURL, rewriteMatchedPath, result.passHostHeader, pt.PathRewrite, pt.CustomHeaders, result.stripAuthHeaders),
		Transport:     p.transport,
		FlushInterval: -1,
		ErrorHandler:  p.proxyErrorHandler,
	}
	if result.rewriteRedirects {
		rp.ModifyResponse = p.rewriteLocationFunc(effectiveURL, rewriteMatchedPath, r) //nolint:bodyclose
	}
	rp.ServeHTTP(respWriter, r.WithContext(ctx))
}

// buildRoutingStub returns a minimal JSON request body carrying only the
// model and stream fields. It feeds the LLM request parser when the real
// body was too large to capture: the parser emits llm.model / llm.stream
// so llm_router can route, while ExtractPrompt on the stub yields nothing
// — no prompt is captured for oversized requests.
func buildRoutingStub(model string, stream bool) []byte {
	b, err := json.Marshal(map[string]any{"model": model, "stream": stream})
	if err != nil {
		return nil
	}
	return b
}

// applyUpstreamRewrite returns the effective upstream URL after
// applying a middleware-emitted rewrite. When rewrite is nil or
// incomplete, the original target is returned unchanged. The original
// URL is never mutated; a clone is returned when a rewrite applies.
//
// Rewrite Path semantics: when non-empty, replaces the cloned URL's
// path entirely. httputil.ProxyRequest.SetURL then joins target.Path
// with the agent's request path, so an operator-configured upstream
// path like "/v1/{account}/{gateway}/compat" gets prepended to
// "/chat/completions" yielding the full Cloudflare-shaped path.
// Empty rewrite.Path preserves the original target's path (the
// historical, non-agent-network behavior).
func applyUpstreamRewrite(orig *url.URL, rewrite *middleware.UpstreamRewrite) *url.URL {
	if rewrite == nil || orig == nil {
		return orig
	}
	if rewrite.Scheme == "" || rewrite.Host == "" {
		return orig
	}
	cloned := *orig
	cloned.Scheme = rewrite.Scheme
	cloned.Host = rewrite.Host
	if rewrite.Path != "" {
		cloned.Path = rewrite.Path
		cloned.RawPath = ""
	}
	return &cloned
}

// stripUpstreamPathPrefix removes a gateway-namespace prefix (e.g. "/bedrock")
// from the request path before it is forwarded, so the upstream receives its
// native path. The chain has already run by this point, so metering/logging
// keep the original client path; only the outbound path is rewritten. RawPath
// is cleared so the escaped form is recomputed from the trimmed Path.
func stripUpstreamPathPrefix(r *http.Request, prefix string) {
	if r == nil || r.URL == nil || prefix == "" {
		return
	}
	if !strings.HasPrefix(r.URL.Path, prefix+"/") && r.URL.Path != prefix {
		return
	}
	r.URL.Path = strings.TrimPrefix(r.URL.Path, prefix)
	if r.URL.Path == "" {
		r.URL.Path = "/"
	}
	r.URL.RawPath = ""
}

// applyUpstreamHeaders strips the headers the rewrite asks for and
// injects the resolved auth header on the in-flight request. It is
// the proxy-trusted counterpart to chain.applyMutations: regular
// middleware HeadersAdd/HeadersRemove pass through the framework
// denylist (which blocks Authorization, Cookie, etc.), but the
// router middleware needs to replace Authorization on the upstream
// request as a first-class operation. AuthHeader/StripHeaders ride
// on UpstreamRewrite so only the proxy's upstream-build path
// unpacks them — middlewares can't smuggle these in via the
// regular mutation surface.
func applyUpstreamHeaders(r *http.Request, rewrite *middleware.UpstreamRewrite) {
	if r == nil || rewrite == nil {
		return
	}
	for _, name := range rewrite.StripHeaders {
		if name == "" {
			continue
		}
		r.Header.Del(name)
	}
	if rewrite.AuthHeader != nil && rewrite.AuthHeader.Name != "" {
		r.Header.Set(rewrite.AuthHeader.Name, rewrite.AuthHeader.Value)
	}
}

// resolveChain returns the middleware chain registered for the
// resolved target, or nil when middleware is disabled for the proxy
// or the target.
func (p *ReverseProxy) resolveChain(result targetResult) *middleware.Chain {
	if p.middlewareManager == nil {
		return nil
	}
	return p.middlewareManager.ChainFor(string(result.serviceID), result.matchedPath)
}

// buildRequestInput gathers the per-request fields the middleware
// chain needs. Body and captured metadata are passed in; the rest are
// copied from the request and CapturedData.
func buildRequestInput(r *http.Request, result targetResult, cd *CapturedData, body []byte, truncated bool, originalSize int64) *middleware.Input {
	in := &middleware.Input{
		Slot:             middleware.SlotOnRequest,
		TargetID:         result.matchedPath,
		Method:           r.Method,
		URL:              r.URL.String(),
		Headers:          headerToKV(r.Header),
		Body:             body,
		BodyTruncated:    truncated,
		OriginalBodySize: originalSize,
		ServiceID:        string(result.serviceID),
		AccountID:        string(result.accountID),
		AgentNetwork:     result.target != nil && result.target.AgentNetwork,
	}
	if cd != nil {
		in.RequestID = cd.GetRequestID()
		in.UserID = cd.GetUserID()
		in.UserEmail = cd.GetUserEmail()
		in.UserGroups = cd.GetUserGroups()
		in.UserGroupNames = cd.GetUserGroupNames()
		in.AuthMethod = cd.GetAuthMethod()
		if ip := cd.GetClientIP(); ip.IsValid() {
			in.SourceIP = ip.String()
		}
	}
	return in
}

// headerToKV flattens an http.Header into the KV slice shape expected
// by the middleware envelope, preserving value order under the same
// key.
func headerToKV(h http.Header) []middleware.KV {
	if len(h) == 0 {
		return nil
	}
	total := 0
	for _, v := range h {
		total += len(v)
	}
	out := make([]middleware.KV, 0, total)
	for k, vs := range h {
		for _, v := range vs {
			out = append(out, middleware.KV{Key: k, Value: v})
		}
	}
	return out
}

// isSelfTargetLoop reports whether an overlay-origin request is about to
// be forwarded back to the very peer that initiated it. The detection
// is intentionally narrow: it only fires when the request arrived on
// the per-account inbound (overlay) listener (so we're confident the
// source address is the caller's tunnel IP), and only when the resolved
// target host matches that tunnel IP. Catching this here returns 421 to
// the caller instead of letting the proxy round-trip its own traffic
// over WG twice.
func (p *ReverseProxy) isSelfTargetLoop(r *http.Request, target *url.URL) bool {
	if target == nil {
		return false
	}
	if !types.IsOverlayOrigin(r.Context()) {
		return false
	}
	srcIP := trustedproxy.ExtractHostIP(r.RemoteAddr)
	if !srcIP.IsValid() {
		return false
	}
	targetIP, err := netip.ParseAddr(target.Hostname())
	if err != nil {
		return false
	}
	return srcIP.Unmap() == targetIP.Unmap()
}

// rewriteFunc returns a Rewrite function for httputil.ReverseProxy that rewrites
// inbound requests to target the backend service while setting security-relevant
// forwarding headers and stripping proxy authentication credentials.
// When passHostHeader is true, the original client Host header is preserved
// instead of being rewritten to the backend's address.
// The pathRewrite parameter controls how the request path is transformed.
func (p *ReverseProxy) rewriteFunc(target *url.URL, matchedPath string, passHostHeader bool, pathRewrite PathRewriteMode, customHeaders map[string]string, stripAuthHeaders []string) func(r *httputil.ProxyRequest) {
	return func(r *httputil.ProxyRequest) {
		switch pathRewrite {
		case PathRewritePreserve:
			// Keep the full original request path as-is.
		default:
			if matchedPath != "" && matchedPath != "/" {
				// Strip the matched path prefix from the incoming request path before
				// SetURL joins it with the target's base path, avoiding path duplication.
				r.Out.URL.Path = strings.TrimPrefix(r.Out.URL.Path, matchedPath)
				if r.Out.URL.Path == "" {
					r.Out.URL.Path = "/"
				}
				r.Out.URL.RawPath = ""
			}
		}

		r.SetURL(target)
		if passHostHeader {
			r.Out.Host = r.In.Host
		} else {
			r.Out.Host = target.Host
		}

		for _, h := range stripAuthHeaders {
			r.Out.Header.Del(h)
		}

		for k, v := range customHeaders {
			r.Out.Header.Set(k, v)
		}

		stampNetBirdIdentity(r)

		clientIP := trustedproxy.ExtractHostIP(r.In.RemoteAddr)

		if p.trustedProxies.Contains(clientIP) {
			p.setTrustedForwardingHeaders(r, clientIP)
		} else {
			p.setUntrustedForwardingHeaders(r, clientIP)
		}

		stripSessionCookie(r)
		stripSessionTokenQuery(r)
	}
}

// rewriteLocationFunc returns a ModifyResponse function that rewrites Location
// headers in backend responses when they point to the backend's address,
// replacing them with the public-facing host and scheme.
func (p *ReverseProxy) rewriteLocationFunc(target *url.URL, matchedPath string, inReq *http.Request) func(*http.Response) error {
	publicHost := inReq.Host
	publicScheme := auth.ResolveProto(p.forwardedProto, inReq.TLS)

	return func(resp *http.Response) error {
		location := resp.Header.Get("Location")
		if location == "" {
			return nil
		}

		locURL, err := url.Parse(location)
		if err != nil {
			return fmt.Errorf("parse Location header %q: %w", location, err)
		}

		// Only rewrite absolute URLs that point to the backend.
		if locURL.Host == "" || !hostsEqual(locURL, target) {
			return nil
		}

		locURL.Host = publicHost
		locURL.Scheme = publicScheme

		// Re-add the stripped path prefix so the client reaches the correct route.
		// TrimRight prevents double slashes when matchedPath has a trailing slash.
		if matchedPath != "" && matchedPath != "/" {
			locURL.Path = strings.TrimRight(matchedPath, "/") + "/" + strings.TrimLeft(locURL.Path, "/")
		}

		resp.Header.Set("Location", locURL.String())
		return nil
	}
}

// hostsEqual compares two URL authorities, normalizing default ports per
// RFC 3986 Section 6.2.3 (https://443 == https, http://80 == http).
func hostsEqual(a, b *url.URL) bool {
	return normalizeHost(a) == normalizeHost(b)
}

// normalizeHost strips the port from a URL's Host field if it matches the
// scheme's default port (443 for https, 80 for http).
func normalizeHost(u *url.URL) string {
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		return u.Host
	}
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		return host
	}
	return u.Host
}

// setTrustedForwardingHeaders appends to the existing forwarding header chain
// and preserves upstream-provided headers when the direct connection is from
// a trusted proxy.
func (p *ReverseProxy) setTrustedForwardingHeaders(r *httputil.ProxyRequest, clientIP netip.Addr) {
	ipStr := clientIP.String()

	// Append the direct connection IP to the existing X-Forwarded-For chain.
	if existing := r.In.Header.Get("X-Forwarded-For"); existing != "" {
		r.Out.Header.Set("X-Forwarded-For", existing+", "+ipStr)
	} else {
		r.Out.Header.Set("X-Forwarded-For", ipStr)
	}

	// Preserve upstream X-Real-IP if present; otherwise resolve through the chain.
	if realIP := r.In.Header.Get("X-Real-IP"); realIP != "" {
		r.Out.Header.Set("X-Real-IP", realIP)
	} else {
		resolved := p.trustedProxies.ResolveClientIP(r.In.RemoteAddr, r.In.Header.Get("X-Forwarded-For"))
		r.Out.Header.Set("X-Real-IP", resolved.String())
	}

	// Preserve upstream X-Forwarded-Host if present.
	if fwdHost := r.In.Header.Get("X-Forwarded-Host"); fwdHost != "" {
		r.Out.Header.Set("X-Forwarded-Host", fwdHost)
	} else {
		r.Out.Header.Set("X-Forwarded-Host", r.In.Host)
	}

	// Trust upstream X-Forwarded-Proto; fall back to local resolution.
	if fwdProto := r.In.Header.Get("X-Forwarded-Proto"); fwdProto != "" {
		r.Out.Header.Set("X-Forwarded-Proto", fwdProto)
	} else {
		r.Out.Header.Set("X-Forwarded-Proto", auth.ResolveProto(p.forwardedProto, r.In.TLS))
	}

	// Trust upstream X-Forwarded-Port; fall back to local computation.
	if fwdPort := r.In.Header.Get("X-Forwarded-Port"); fwdPort != "" {
		r.Out.Header.Set("X-Forwarded-Port", fwdPort)
	} else {
		resolvedProto := r.Out.Header.Get("X-Forwarded-Proto")
		r.Out.Header.Set("X-Forwarded-Port", extractForwardedPort(r.In.Host, resolvedProto))
	}
}

// setUntrustedForwardingHeaders strips all incoming forwarding headers and
// sets them fresh based on the direct connection. This is the default
// behavior when no trusted proxies are configured or the direct connection
// is from an untrusted source.
func (p *ReverseProxy) setUntrustedForwardingHeaders(r *httputil.ProxyRequest, clientIP netip.Addr) {
	ipStr := clientIP.String()
	proto := auth.ResolveProto(p.forwardedProto, r.In.TLS)
	r.Out.Header.Set("X-Forwarded-For", ipStr)
	r.Out.Header.Set("X-Real-IP", ipStr)
	r.Out.Header.Set("X-Forwarded-Host", r.In.Host)
	r.Out.Header.Set("X-Forwarded-Proto", proto)
	r.Out.Header.Set("X-Forwarded-Port", extractForwardedPort(r.In.Host, proto))
}

// stripSessionCookie removes the proxy's session cookie from the outgoing
// request while preserving all other cookies.
//
// IMPORTANT: This must operate on the raw Cookie header. Go's
// Request.Cookies()/AddCookie() path drops cookie values that contain
// characters outside RFC 6265 cookie-octet (e.g. `"`, `,`, `{`, `}`).
// OIDC providers such as Logto/node-oidc-provider store interaction state
// as JSON in cookies (_interaction, _logto, …). Re-serializing via
// Cookies()+AddCookie silently strips those cookies and breaks upstream
// auth flows (redirect loops to /unknown-session, missing sessions, etc.).
func stripSessionCookie(r *httputil.ProxyRequest) {
	raw := r.In.Header.Get("Cookie")
	if raw == "" {
		r.Out.Header.Del("Cookie")
		return
	}

	parts := strings.Split(raw, ";")
	kept := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, _, _ := strings.Cut(part, "=")
		if name == auth.SessionCookieName {
			continue
		}
		kept = append(kept, part)
	}

	if len(kept) == 0 {
		r.Out.Header.Del("Cookie")
		return
	}
	r.Out.Header.Set("Cookie", strings.Join(kept, "; "))
}

// stripSessionTokenQuery removes the OIDC session_token query parameter from
// the outgoing URL to prevent credential leakage to backends.
func stripSessionTokenQuery(r *httputil.ProxyRequest) {
	q := r.Out.URL.Query()
	if q.Has("session_token") {
		q.Del("session_token")
		r.Out.URL.RawQuery = q.Encode()
	}
}

// extractForwardedPort returns the port from the Host header if present,
// otherwise defaults to the standard port for the resolved protocol.
func extractForwardedPort(host, resolvedProto string) string {
	_, port, err := net.SplitHostPort(host)
	if err == nil && port != "" {
		return port
	}
	if resolvedProto == "https" {
		return "443"
	}
	return "80"
}

// proxyErrorHandler handles errors from the reverse proxy and serves
// user-friendly error pages instead of raw error responses.
func (p *ReverseProxy) proxyErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	if cd := CapturedDataFromContext(r.Context()); cd != nil {
		cd.SetOrigin(OriginProxyError)
	}
	requestID := getRequestID(r)
	clientIP := getClientIP(r)
	title, message, code, status := classifyProxyError(err)

	p.logger.Warnf("proxy error: request_id=%s client_ip=%s method=%s host=%s path=%s status=%d title=%q err=%v",
		requestID, clientIP, r.Method, r.Host, r.URL.Path, code, title, err)

	web.ServeErrorPage(w, r, code, title, message, requestID, status)
}

// getClientIP retrieves the resolved client IP string from context.
func getClientIP(r *http.Request) string {
	if capturedData := CapturedDataFromContext(r.Context()); capturedData != nil {
		if ip := capturedData.GetClientIP(); ip.IsValid() {
			return ip.String()
		}
	}
	return ""
}

// getRequestID retrieves the request ID from context or returns empty string.
func getRequestID(r *http.Request) string {
	if capturedData := CapturedDataFromContext(r.Context()); capturedData != nil {
		return capturedData.GetRequestID()
	}
	return ""
}

// classifyProxyError determines the appropriate error title, message, HTTP
// status code, and component status based on the error type.
func classifyProxyError(err error) (title, message string, code int, status web.ErrorStatus) {
	switch {
	case errors.Is(err, context.DeadlineExceeded),
		isNetTimeout(err):
		return "Request Timeout",
			"The request timed out while trying to reach the service. Please refresh the page and try again.",
			http.StatusGatewayTimeout,
			web.ErrorStatus{Proxy: true, Destination: false}

	case errors.Is(err, context.Canceled):
		return "Request Canceled",
			"The request was canceled before it could be completed. Please refresh the page and try again.",
			http.StatusBadGateway,
			web.ErrorStatus{Proxy: true, Destination: false}

	case errors.Is(err, roundtrip.ErrNoAccountID):
		return "Configuration Error",
			"The request could not be processed due to a configuration issue. Please refresh the page and try again.",
			http.StatusInternalServerError,
			web.ErrorStatus{Proxy: false, Destination: false}

	case errors.Is(err, roundtrip.ErrNoPeerConnection),
		errors.Is(err, roundtrip.ErrClientStartFailed):
		return "Proxy Not Connected",
			"The proxy is not connected to the NetBird network. Please try again later or contact your administrator.",
			http.StatusBadGateway,
			web.ErrorStatus{Proxy: false, Destination: false}

	case errors.Is(err, roundtrip.ErrTooManyInflight):
		return "Service Overloaded",
			"The service is currently handling too many requests. Please try again shortly.",
			http.StatusServiceUnavailable,
			web.ErrorStatus{Proxy: true, Destination: false}

	case isConnectionRefused(err):
		return "Service Unavailable",
			"The connection to the service was refused. Please verify that the service is running and try again.",
			http.StatusBadGateway,
			web.ErrorStatus{Proxy: true, Destination: false}

	case isHostUnreachable(err):
		return "Peer Not Connected",
			"The connection to the peer could not be established. Please ensure the peer is running and connected to the NetBird network.",
			http.StatusBadGateway,
			web.ErrorStatus{Proxy: true, Destination: false}
	}

	return "Connection Error",
		"An unexpected error occurred while connecting to the service. Please try again later.",
		http.StatusBadGateway,
		web.ErrorStatus{Proxy: true, Destination: false}
}

// isConnectionRefused checks for connection refused errors by inspecting
// the inner error of a *net.OpError. This handles both standard net errors
// (where the inner error is a *os.SyscallError with "connection refused")
// and gVisor netstack errors ("connection was refused").
func isConnectionRefused(err error) bool {
	return opErrorContains(err, "refused")
}

// isHostUnreachable checks for host/network unreachable errors by inspecting
// the inner error of a *net.OpError. Covers standard net ("no route to host",
// "network is unreachable") and gVisor ("host is unreachable", etc.).
func isHostUnreachable(err error) bool {
	return opErrorContains(err, "unreachable") || opErrorContains(err, "no route to host")
}

// isNetTimeout checks whether the error is a network timeout using the
// net.Error interface.
func isNetTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// opErrorContains extracts the inner error from a *net.OpError and checks
// whether its message contains the given substring. This handles gVisor
// netstack errors which wrap tcpip errors as plain strings rather than
// syscall.Errno values.
func opErrorContains(err error, substr string) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Err != nil {
		return strings.Contains(opErr.Err.Error(), substr)
	}
	return false
}

const (
	// headerNetBirdUser carries the authenticated user's display identity
	// (email when the peer is attached to a user, else peer name) onto
	// upstream requests. Stripped from inbound requests before stamping
	// so a client can't spoof identity by setting the header themselves.
	headerNetBirdUser = "X-NetBird-User"
	// headerNetBirdGroups carries the user's group display names as a
	// comma-separated list. Falls back to group IDs at positions where a
	// name wasn't available at session-mint time. Labels containing a
	// comma or any non-printable byte are dropped at stamp time so the
	// list is unambiguously splittable by consumers.
	headerNetBirdGroups = "X-NetBird-Groups"

	// observabilityPhaseTimeout bounds the detached response/terminal
	// metering phase. It runs after the client connection (and its context)
	// may be gone, so it can't borrow the request deadline; this ceiling
	// keeps a slow management round-trip (RecordLLMUsage) from pinning the
	// handler goroutine indefinitely while still allowing each middleware
	// its own per-invoke timeout.
	observabilityPhaseTimeout = 30 * time.Second
)

// isHeaderValueSafe reports whether v is a valid RFC 7230 field-value:
// VCHAR (0x21-0x7E), SP (0x20), or HTAB (0x09). Empty values are
// rejected; the caller decides whether to omit the header entirely.
func isHeaderValueSafe(v string) bool {
	if v == "" {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c == '\t' || (c >= 0x20 && c <= 0x7E) {
			continue
		}
		return false
	}
	return true
}

// stampNetBirdIdentity injects authenticated identity onto outbound
// requests as X-NetBird-User and X-NetBird-Groups. Always strips any
// client-sent values first (anti-spoof). Skips when the request didn't
// carry CapturedData (early-path errors, internal endpoints).
func stampNetBirdIdentity(r *httputil.ProxyRequest) {
	r.Out.Header.Del(headerNetBirdUser)
	r.Out.Header.Del(headerNetBirdGroups)

	cd := CapturedDataFromContext(r.In.Context())
	if cd == nil {
		return
	}
	if email := cd.GetUserEmail(); isHeaderValueSafe(email) {
		r.Out.Header.Set(headerNetBirdUser, email)
	}
	groupIDs := cd.GetUserGroups()
	if len(groupIDs) == 0 {
		return
	}
	groupNames := cd.GetUserGroupNames()
	labels := make([]string, 0, len(groupIDs))
	for i, id := range groupIDs {
		label := id
		if i < len(groupNames) && groupNames[i] != "" {
			label = groupNames[i]
		}
		if !isHeaderValueSafe(label) || strings.ContainsRune(label, ',') {
			continue
		}
		labels = append(labels, label)
	}
	if len(labels) > 0 {
		r.Out.Header.Set(headerNetBirdGroups, strings.Join(labels, ","))
	}
}
