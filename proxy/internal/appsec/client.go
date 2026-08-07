// Package appsec implements the CrowdSec AppSec (WAF) side of the remediation
// component protocol: each inspected HTTP request is mirrored to the Security
// Engine's AppSec endpoint, which replies with an allow / ban / captcha verdict
// for that request.
//
// This is a separate endpoint from the LAPI decision stream used by the
// crowdsec package: LAPI answers "is this IP known bad", AppSec answers "is
// this request an attack". The two are configured and enabled independently.
package appsec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/proxy/internal/netutil"
	"github.com/netbirdio/netbird/proxy/internal/restrict"
)

// Header names the AppSec component reads off the mirrored request. IP, URI and
// Verb are mandatory: the engine answers 500 when any of them is missing.
const (
	headerAPIKey        = "X-Crowdsec-Appsec-Api-Key" //nolint:gosec // G101: a header name, not a credential
	headerIP            = "X-Crowdsec-Appsec-Ip"
	headerURI           = "X-Crowdsec-Appsec-Uri"
	headerVerb          = "X-Crowdsec-Appsec-Verb"
	headerHost          = "X-Crowdsec-Appsec-Host"
	headerUserAgent     = "X-Crowdsec-Appsec-User-Agent"
	headerHTTPVersion   = "X-Crowdsec-Appsec-Http-Version"
	headerTransactionID = "X-Crowdsec-Appsec-Transaction-Id"
)

// headerPrefix covers every protocol header. Any client-supplied header in this
// namespace is dropped before forwarding so a caller cannot influence the
// engine's view of its own address, or replay an API key.
const headerPrefix = "X-Crowdsec-Appsec-"

// Remediation actions the engine can return.
const (
	actionAllow   = "allow"
	actionBan     = "ban"
	actionCaptcha = "captcha"
)

const (
	// DefaultTimeout matches the 200ms budget CrowdSec's remediation component
	// spec sets for the blocking AppSec call.
	DefaultTimeout = 200 * time.Millisecond
	// MinTimeout and MaxTimeout bound the configured inspection timeout.
	// Inspection is synchronous, so the upper bound is what keeps a
	// mis-set value from parking every request to an inspected service on a
	// slow engine; the lower bound keeps the call from timing out before the
	// engine can realistically answer. Mirrors the per-middleware bounds the
	// proxy already applies to in-path calls.
	MinTimeout = 10 * time.Millisecond
	MaxTimeout = 5 * time.Second
	// DefaultMaxBodyBytes caps the request body mirrored to the engine.
	// Requests with a larger body are inspected on headers and URI only.
	DefaultMaxBodyBytes int64 = 64 << 10
	// DefaultMaxConcurrent bounds inspections in flight toward the engine. The
	// point is to fail fast instead of parking a goroutine per request for the
	// whole timeout once the engine is saturated: a slow engine otherwise turns
	// a traffic burst into a pile of waiters that all time out anyway. Sized so
	// a healthy engine (single-digit milliseconds per call) never reaches it.
	DefaultMaxConcurrent = 256
	// MaxConcurrentLimit is the ceiling for that bound.
	MaxConcurrentLimit = 4096
	// MaxBodyBytesLimit is the ceiling for that cap. A single request can hold
	// this much in memory; the shared Budget is what bounds the total across
	// concurrent requests. Matches the proxy-wide body-capture ceiling.
	MaxBodyBytesLimit int64 = 8 << 20
	// maxResponseBytes bounds how much of a verdict response is read. The
	// engine answers with a two-field JSON object, so anything beyond this is
	// not a response we can act on.
	maxResponseBytes int64 = 4 << 10
)

// Reasons the request body was not mirrored. Reported so an access-log reader
// can distinguish "inspected and clean" from "never inspected", and so an
// oversize opt-out is visible rather than silent.
const (
	BypassOversize = "oversize"
	BypassUpgrade  = "upgrade"
	BypassDisabled = "disabled"
	BypassBudget   = "budget_exhausted"
)

// ErrUnavailable reports that the engine could not produce a verdict: the call
// failed, timed out, or the engine rejected it (401 bad key, 500 malformed).
// Distinguished from a block verdict so the caller can apply the per-service
// mode: enforce fails closed, observe allows.
var ErrUnavailable = errors.New("appsec engine unavailable")

// Config configures a Client.
type Config struct {
	// URL is the AppSec endpoint, e.g. http://127.0.0.1:7422/.
	URL string
	// APIKey is the CrowdSec bouncer API key. The AppSec component validates it
	// against LAPI, so the same key used for the decision stream works here.
	APIKey string
	// Timeout bounds a single inspection call. Zero means DefaultTimeout.
	Timeout time.Duration
	// MaxBodyBytes caps the mirrored request body. Zero means
	// DefaultMaxBodyBytes; negative disables body forwarding entirely.
	MaxBodyBytes int64
	// MaxConcurrent bounds inspections in flight toward the engine. Zero means
	// DefaultMaxConcurrent; negative disables the bound.
	MaxConcurrent int
	// Budget bounds the total body buffering in flight across all inspected
	// requests. Nil disables that ceiling, which leaves the worst case at
	// MaxBodyBytes times the concurrent request count; callers serving
	// untrusted traffic should share the proxy-wide capture budget here.
	Budget Budget
	Logger *log.Entry
}

// Budget is the shared allowance for in-flight body buffering. Acquire reports
// whether n bytes could be reserved; every successful Acquire is matched by a
// Release of the same n. Satisfied by the proxy's capture budget, so AppSec and
// the middleware body tap draw down one pool rather than two independent ones.
type Budget interface {
	Acquire(n int64) bool
	Release(n int64)
}

// Client mirrors HTTP requests to a CrowdSec AppSec endpoint. It holds no
// per-service state and is safe for concurrent use.
type Client struct {
	url          string
	apiKey       string
	maxBodyBytes int64
	// sem bounds in-flight inspections. Nil when the bound is disabled.
	sem    chan struct{}
	budget Budget
	http   *http.Client
	logger *log.Entry
}

// New validates the config and returns a Client. The endpoint is not contacted
// here: the engine may come up after the proxy.
func New(cfg Config) (*Client, error) {
	if cfg.URL == "" {
		return nil, errors.New("appsec url is empty")
	}
	if cfg.APIKey == "" {
		return nil, errors.New("appsec api key is empty")
	}
	parsed, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("parse appsec url: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("appsec url scheme %q is not http(s)", parsed.Scheme)
	}
	if parsed.Host == "" {
		return nil, errors.New("appsec url has no host")
	}

	logger := cfg.Logger
	if logger == nil {
		logger = log.NewEntry(log.StandardLogger())
	}

	timeout := cfg.Timeout
	switch {
	case timeout <= 0:
		timeout = DefaultTimeout
	case timeout < MinTimeout:
		logger.Warnf("appsec timeout %s is below the minimum, using %s", timeout, MinTimeout)
		timeout = MinTimeout
	case timeout > MaxTimeout:
		logger.Warnf("appsec timeout %s exceeds the maximum, using %s", timeout, MaxTimeout)
		timeout = MaxTimeout
	}

	// A negative cap is meaningful: forward no body at all.
	maxBody := cfg.MaxBodyBytes
	switch {
	case maxBody == 0:
		maxBody = DefaultMaxBodyBytes
	case maxBody > MaxBodyBytesLimit:
		logger.Warnf("appsec max body %d exceeds the maximum, using %d", maxBody, MaxBodyBytesLimit)
		maxBody = MaxBodyBytesLimit
	}

	maxConcurrent := cfg.MaxConcurrent
	switch {
	case maxConcurrent == 0:
		maxConcurrent = DefaultMaxConcurrent
	case maxConcurrent > MaxConcurrentLimit:
		logger.Warnf("appsec max concurrent %d exceeds the maximum, using %d", maxConcurrent, MaxConcurrentLimit)
		maxConcurrent = MaxConcurrentLimit
	}
	var sem chan struct{}
	if maxConcurrent > 0 {
		sem = make(chan struct{}, maxConcurrent)
	}

	return &Client{
		url:          cfg.URL,
		apiKey:       cfg.APIKey,
		maxBodyBytes: maxBody,
		sem:          sem,
		budget:       cfg.Budget,
		logger:       logger,
		http: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 32,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}, nil
}

// Request is one inspection request.
type Request struct {
	// HTTP is the in-flight client request. Inspect buffers and restores its
	// body, so the request stays forwardable afterwards.
	HTTP *http.Request
	// ClientIP is the resolved client address (after trusted-proxy handling).
	ClientIP netip.Addr
	// TransactionID correlates the engine's alert with the proxy's access log
	// entry. Empty lets the engine generate its own UUID.
	TransactionID string
	// RedactBodyFields lists form fields whose values are replaced before the
	// body is mirrored. Used to keep credentials submitted to the proxy's own
	// login form out of the engine while still inspecting the rest.
	RedactBodyFields []string
	// RedactHeaders, RedactCookies and RedactQueryParams name the credentials
	// the proxy already withholds from backends: the header-auth values, its
	// session cookie, and the OIDC session token. The engine logs and alerts on
	// what it inspects, so mirroring them there would reintroduce the leak the
	// upstream strippers exist to prevent. Only the values are replaced, so the
	// surrounding headers, cookies and query stay inspectable.
	RedactHeaders     []string
	RedactCookies     []string
	RedactQueryParams []string
}

// Result is the outcome of an inspection.
type Result struct {
	Verdict restrict.Verdict
	// BodyBypass names why the request body was not mirrored, empty when it
	// was (or when the request had none). The engine still saw the headers and
	// URI, so this is a coverage note, not a failure.
	BodyBypass string
	// Release returns the buffered body's budget reservation. Never nil, so it
	// is always safe to defer. It must run only once the request has been
	// served, not when Inspect returns: the buffer stays alive as r.Body for
	// the backend to read, so releasing earlier would let the budget admit
	// buffering that is still resident.
	Release func()
}

// noopRelease is the Release for inspections that reserved no budget.
func noopRelease() {}

// Inspect mirrors r to the AppSec engine and returns its verdict. A nil error
// with restrict.Allow means the request passed. On failure it returns
// DenyAppSecUnavailable wrapped with ErrUnavailable; the caller decides whether
// that blocks, based on the per-service mode.
func (c *Client) Inspect(ctx context.Context, req Request) (Result, error) {
	if c == nil {
		return Result{Verdict: restrict.DenyAppSecUnavailable, Release: noopRelease}, ErrUnavailable
	}
	if req.HTTP == nil {
		return Result{Verdict: restrict.DenyAppSecUnavailable, Release: noopRelease}, fmt.Errorf("%w: nil request", ErrUnavailable)
	}

	// release is carried out to the caller rather than deferred here: the
	// buffered body outlives this call as r.Body.
	if !c.acquireSlot() {
		// Deny rather than wave through: a flood must not be a way to switch
		// inspection off. Enforce blocks, observe logs and allows, exactly as
		// for an unreachable engine.
		return Result{Verdict: restrict.DenyAppSecUnavailable, Release: noopRelease},
			fmt.Errorf("%w: %d inspections already in flight", ErrUnavailable, cap(c.sem))
	}
	defer c.releaseSlot()

	body, bypass, release, err := c.readBody(req)
	if err != nil {
		return Result{Verdict: restrict.DenyAppSecUnavailable, Release: release}, fmt.Errorf("%w: read body: %w", ErrUnavailable, err)
	}

	outbound, err := c.buildRequest(ctx, req, body)
	if err != nil {
		return Result{Verdict: restrict.DenyAppSecUnavailable, BodyBypass: bypass, Release: release}, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}

	resp, err := c.http.Do(outbound)
	if err != nil {
		return Result{Verdict: restrict.DenyAppSecUnavailable, BodyBypass: bypass, Release: release}, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	defer func() {
		// Drain before closing. net/http only returns a connection to the idle
		// pool once its body is read to EOF; closing with bytes outstanding
		// discards it. Every verdict carries a JSON body, so skipping this
		// would cost a fresh handshake per inspected request, inside the
		// timeout budget.
		if _, err := io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes)); err != nil {
			c.logger.Tracef("drain appsec response body: %v", err)
		}
		if err := resp.Body.Close(); err != nil {
			c.logger.Tracef("close appsec response body: %v", err)
		}
	}()

	verdict, err := c.verdict(resp)
	return Result{Verdict: verdict, BodyBypass: bypass, Release: release}, err
}

// acquireSlot takes an in-flight slot without blocking, reporting false when
// the engine is already at capacity.
func (c *Client) acquireSlot() bool {
	if c.sem == nil {
		return true
	}
	select {
	case c.sem <- struct{}{}:
		return true
	default:
		return false
	}
}

// releaseSlot returns the slot. Scoped to the engine call, not the request: the
// buffered body outlives the call but the engine's attention does not.
func (c *Client) releaseSlot() {
	if c.sem == nil {
		return
	}
	select {
	case <-c.sem:
	default:
	}
}

// readBody buffers the body so it can be mirrored, always restoring it on the
// original request. Returns nil when there is no body to forward: no body at
// all, an upgrade request, or a body over the cap. A login form is forwarded
// with its credential values redacted rather than suppressed.
// release is never nil; the caller invokes it once the request has been served.
func (c *Client) readBody(req Request) (body []byte, bypass string, release func(), err error) {
	r := req.HTTP
	if r.Body == nil || r.Body == http.NoBody {
		return nil, "", noopRelease, nil
	}
	if c.maxBodyBytes < 0 {
		return nil, BypassDisabled, noopRelease, nil
	}
	// A genuine upgrade request carries no body to inspect (net/http hands us
	// http.NoBody, caught above); the hijacked stream is reached through
	// Hijacker, never r.Body. The test has to be the forwarder's own, because a
	// looser one would skip inspection for requests the forwarder still
	// delivers to the backend with their body intact.
	if netutil.IsUpgradeRequest(r.Header) {
		return nil, BypassUpgrade, noopRelease, nil
	}
	// A Content-Length over the cap is known to be too large before reading.
	if r.ContentLength > c.maxBodyBytes {
		return nil, BypassOversize, noopRelease, nil
	}

	// Reserve the whole cap rather than the eventual length: the reservation
	// has to be made before the body is read, and until then the only bound
	// known is the cap. Skipping inspection when the pool is drained keeps a
	// burst of large bodies from being an out-of-memory lever; the bypass is
	// recorded so the gap in coverage is visible.
	release = noopRelease
	if c.budget != nil {
		if !c.budget.Acquire(c.maxBodyBytes) {
			c.logger.Debugf("appsec buffer budget exhausted, inspecting headers and URI only")
			return nil, BypassBudget, noopRelease, nil
		}
		var once sync.Once
		release = func() { once.Do(func() { c.budget.Release(c.maxBodyBytes) }) }
	}

	buffered, oversize, err := bufferBody(r, c.maxBodyBytes)
	if err != nil {
		// bufferBody restored r.Body from the bytes it did read, so the
		// reservation stays held until the caller releases it.
		return nil, "", release, err
	}
	// An oversize body was only partially read: a truncated prefix changes the
	// engine's verdict in both directions, so inspect headers and URI only.
	if oversize {
		return nil, BypassOversize, release, nil
	}
	return redactFormFields(r.Header.Get("Content-Type"), buffered, req.RedactBodyFields), "", release, nil
}

// buildRequest assembles the mirrored request. Per the protocol it is a GET
// when there is no body and a POST otherwise; bytes.Reader gives the outbound
// request an accurate Content-Length, which the engine relies on to read the
// body at all.
func (c *Client) buildRequest(ctx context.Context, req Request, body []byte) (*http.Request, error) {
	method := http.MethodGet
	var payload io.Reader
	if len(body) > 0 {
		method = http.MethodPost
		payload = bytes.NewReader(body)
	}

	outbound, err := http.NewRequestWithContext(ctx, method, c.url, payload)
	if err != nil {
		return nil, fmt.Errorf("build appsec request: %w", err)
	}

	r := req.HTTP
	copyInspectableHeaders(outbound.Header, r.Header)
	redactSecrets(outbound.Header, req)

	outbound.Header.Set(headerAPIKey, c.apiKey)
	outbound.Header.Set(headerIP, req.ClientIP.Unmap().String())
	outbound.Header.Set(headerURI, mirroredURI(r.URL, req.RedactQueryParams))
	outbound.Header.Set(headerVerb, r.Method)
	outbound.Header.Set(headerHost, r.Host)
	if ua := r.UserAgent(); ua != "" {
		outbound.Header.Set(headerUserAgent, ua)
	}
	outbound.Header.Set(headerHTTPVersion, httpVersion(r))
	if req.TransactionID != "" {
		outbound.Header.Set(headerTransactionID, req.TransactionID)
	}
	return outbound, nil
}

// verdict maps the engine's response to a restrict.Verdict. 200 is a pass and
// 401/500 are engine-side failures; every other status carries a remediation in
// the body. The blocked status code is operator-configurable
// (blocked_http_code), so the action field decides, not the status.
func (c *Client) verdict(resp *http.Response) (restrict.Verdict, error) {
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return restrict.DenyAppSecUnavailable, fmt.Errorf("%w: rejected api key", ErrUnavailable)
	case http.StatusInternalServerError:
		return restrict.DenyAppSecUnavailable, fmt.Errorf("%w: engine error", ErrUnavailable)
	}

	// Every status, 200 included, has to carry a decodable remediation. Taking a
	// bare 200 as a pass would mean a URL pointing at anything that answers 200
	// (a health endpoint, a load balancer's default page) silently allows every
	// request while the service reports itself as enforcing.

	var decoded struct {
		Action string `json:"action"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&decoded); err != nil {
		// Every remediation carries a decodable action, so a response without
		// one is not a verdict: most often the URL points at something that is
		// not the AppSec endpoint, which answers 404 with HTML. Reported as
		// unavailable rather than a ban so the access log names the real fault
		// instead of sending an operator hunting for a rule that never fired.
		// Enforce still blocks either way; only the recorded reason differs.
		return restrict.DenyAppSecUnavailable, fmt.Errorf("%w: undecodable response (status %d): %w", ErrUnavailable, resp.StatusCode, err)
	}

	switch decoded.Action {
	case actionAllow:
		return restrict.Allow, nil
	case actionCaptcha:
		return restrict.DenyAppSecCaptcha, nil
	case actionBan:
		return restrict.DenyAppSecBan, nil
	case "":
		// Decodable JSON without a remediation is not a verdict either: the
		// endpoint answered, but not as the engine. Same reasoning as an
		// undecodable body, and the same reason to point at configuration.
		return restrict.DenyAppSecUnavailable,
			fmt.Errorf("%w: response carried no remediation (status %d)", ErrUnavailable, resp.StatusCode)
	default:
		// A remediation we do not implement still means the engine flagged the
		// request, so deny.
		c.logger.Debugf("unknown appsec action %q (status %d), treating as ban", decoded.Action, resp.StatusCode)
		return restrict.DenyAppSecBan, nil
	}
}

// copyInspectableHeaders copies the client's headers, which are what the WAF
// rules actually match on, dropping hop-by-hop headers that describe the
// proxy-to-engine connection rather than the client request, and any header in
// the AppSec protocol namespace.
func copyInspectableHeaders(dst, src http.Header) {
	for name, values := range src {
		if hopByHopHeaders[http.CanonicalHeaderKey(name)] {
			continue
		}
		if strings.HasPrefix(http.CanonicalHeaderKey(name), headerPrefix) {
			continue
		}
		dst[http.CanonicalHeaderKey(name)] = append([]string(nil), values...)
	}
	// Content-Length describes the mirrored payload, not the client's: net/http
	// sets it from the body we actually attach. Content-Type is kept either way
	// so rules matching on it still fire when the body was not forwarded.
	dst.Del("Content-Length")
}

// redactSecrets replaces the credential values the proxy withholds from
// backends, so the mirrored copy does not carry them either.
func redactSecrets(dst http.Header, req Request) {
	for _, name := range req.RedactHeaders {
		// Presence, not Get: a header whose first value is empty still carries
		// its later values to the engine, while the upstream strip deletes the
		// name outright. Set collapses every value into the placeholder.
		if len(dst.Values(name)) > 0 {
			dst.Set(name, redactedPlaceholder)
		}
	}
	// Every Cookie line, not just the first: a client may send several, and Get
	// would leave the session cookie in any later one mirrored in the clear.
	if cookies := dst.Values("Cookie"); len(cookies) > 0 {
		redacted := make([]string, len(cookies))
		for i, cookie := range cookies {
			redacted[i] = redactCookieHeader(cookie, req.RedactCookies)
		}
		dst["Cookie"] = redacted
	}
}

// mirroredURI renders the request target for the URI header, with the named
// query parameter values replaced.
func mirroredURI(u *url.URL, redactParams []string) string {
	uri := u.RequestURI()
	if u.RawQuery == "" || len(redactParams) == 0 {
		return uri
	}
	redacted := redactQuery(u.RawQuery, redactParams)
	if redacted == u.RawQuery {
		return uri
	}
	// RequestURI is path + "?" + RawQuery; swap only the query part so the
	// path keeps its original encoding.
	return strings.TrimSuffix(uri, u.RawQuery) + redacted
}

var hopByHopHeaders = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Proxy-Connection":    true,
	"Te":                  true,
	"Trailer":             true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
}

// httpVersion renders the two-digit form the engine parses ("11", "20").
func httpVersion(r *http.Request) string {
	major, minor := r.ProtoMajor, r.ProtoMinor
	if major < 0 || major > 9 || minor < 0 || minor > 9 {
		return ""
	}
	return fmt.Sprintf("%d%d", major, minor)
}
