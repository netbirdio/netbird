// Package modeldiscovery asks a vendor which models an operator's own
// credential can reach, so the provider form can offer a live list instead of
// only the catalog's hand-curated one.
//
// The catalog cannot know two things that matter. It goes stale — its entries
// carry comments tracking which models a vendor retired on which date — and it
// cannot see an account: which OpenAI models an org is entitled to, which
// Bedrock inference profiles a given account and region hold, which Vertex
// models a project has enabled. Those are exactly the facts an operator needs
// when filling in a provider record, and only the vendor has them.
//
// The vendor is authoritative for the model ID. The catalog remains
// authoritative for pricing, and a discovered model the catalog cannot price
// is reported as such rather than silently registered at a rate of zero.
package modeldiscovery

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"

	"golang.org/x/oauth2/google"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/catalog"
)

const (
	// fetchTimeout bounds one vendor call end to end. A listing is a single
	// small GET; anything slower is a vendor problem and the operator is
	// waiting on a form.
	fetchTimeout = 8 * time.Second
	// maxListingBytes bounds the response we will buffer. The largest real
	// listing observed is Bedrock's foundation-model catalogue at ~70KB, so
	// this is a wide margin over anything legitimate.
	maxListingBytes = 2 << 20
	// gcpScope matches the scope llm_router mints Vertex tokens under, so a
	// credential that works for discovery works for inference too.
	gcpScope = "https://www.googleapis.com/auth/cloud-platform"
	// vertexKeyfilePrefix marks an api_key that is a base64 service-account
	// JSON key rather than a bearer token.
	vertexKeyfilePrefix = "keyfile::"
)

// ErrNoDiscovery is returned for a catalog entry that declares no listing
// endpoint. Gateways vary too much to have one, and the caller should fall
// back to the catalog list plus free-text entry rather than treating this as
// a failure.
var ErrNoDiscovery = errors.New("provider has no model-discovery endpoint")

// ErrInvalidRequest marks a discovery failure caused by the caller's own input
// rather than by the vendor or by this server. Every one of these is reachable
// from a well-formed request carrying a bad field value, so the handler owes
// the caller a 400 — a 500 would both misinform them and bury real server
// faults in the error rate.
var ErrInvalidRequest = errors.New("invalid discovery request")

// Model is one discovered model.
type Model struct {
	// ID is the identifier to register on the provider record, in the form the
	// vendor issues it. For Bedrock that is the region-prefixed inference
	// profile id, which is the only form AWS accepts at invoke time.
	ID string
	// Label is the vendor's display name where it supplies one.
	Label string
	// PricingKnown reports whether the shipped pricing table can price this
	// model. False means the operator must set rates, or the request would
	// meter at zero.
	PricingKnown bool
}

// Request identifies which vendor to ask and with what credential.
type Request struct {
	// CatalogID selects the catalog entry, which supplies the endpoint, the
	// auth header and the response shape. The caller never supplies those.
	CatalogID string
	// UpstreamURL is the provider record's configured upstream. It is used
	// only when the catalog entry declares no discovery host of its own.
	UpstreamURL string
	// Region substitutes the catalog host's <region> placeholder.
	Region string
	// APIKey is the operator's credential, exactly as stored on the record.
	APIKey string
}

// Client fetches model listings. The zero value is usable; Resolver and
// HTTPClient exist so tests can drive it against a local server.
type Client struct {
	HTTPClient *http.Client
	// Resolver looks up the host for the SSRF check. Nil uses the default.
	Resolver *net.Resolver
	// AllowPrivateHosts disables the private-address guard. Only tests set it:
	// their server is on loopback, which is precisely what the guard blocks.
	AllowPrivateHosts bool
}

// Fetch returns the models the credential can reach.
func (c *Client) Fetch(ctx context.Context, req Request) ([]Model, error) {
	entry, ok := catalog.Lookup(req.CatalogID)
	if !ok {
		return nil, fmt.Errorf("%w: unknown catalog provider %q", ErrInvalidRequest, req.CatalogID)
	}
	if entry.Discovery == nil {
		return nil, ErrNoDiscovery
	}

	endpoint, err := c.discoveryURL(entry, req)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build discovery request: %w", err)
	}
	if err := applyAuth(httpReq, entry, req.APIKey); err != nil {
		return nil, err
	}
	for name, value := range entry.Discovery.Headers {
		httpReq.Header.Set(name, value)
	}
	httpReq.Header.Set("Accept", "application/json")

	resp, err := c.httpClient().Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("reach %s: %w", entry.Name, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxListingBytes))
	if err != nil {
		return nil, fmt.Errorf("read %s listing: %w", entry.Name, err)
	}
	if resp.StatusCode != http.StatusOK {
		// Surface the vendor's own status. An operator whose key lacks a scope
		// needs to see 403 rather than a generic failure.
		return nil, fmt.Errorf("%s returned %d for its model listing", entry.Name, resp.StatusCode)
	}

	ids, err := parseListing(entry.Discovery.Shape, body)
	if err != nil {
		return nil, err
	}
	return decorate(entry, ids), nil
}

// discoveryURL builds the listing URL and refuses one that does not point at a
// public host.
//
// The path, query and (for Bedrock) the host all come from the catalog rather
// than from the caller, so the only operator-controlled part is the host of an
// entry whose listing lives on its own upstream. That still has to be checked:
// management holds credentials for every provider, and an upstream pointed at
// an internal address would turn this endpoint into a probe of the management
// server's own network.
func (c *Client) discoveryURL(entry catalog.Provider, req Request) (string, error) {
	host := entry.Discovery.Host
	if host == "" {
		parsed, err := url.Parse(strings.TrimSpace(req.UpstreamURL))
		if err != nil || parsed.Host == "" {
			return "", fmt.Errorf("%w: provider upstream %q is not a usable URL", ErrInvalidRequest, req.UpstreamURL)
		}
		host = parsed.Host
	}
	if strings.Contains(host, catalog.RegionPlaceholder) {
		region := strings.TrimSpace(req.Region)
		if region == "" {
			// A provider record carries no region field: the region lives
			// inside the upstream host the operator already configured, so
			// read it back out rather than asking them for it twice.
			region = regionFromUpstream(entry, req.UpstreamURL)
		}
		if region == "" {
			return "", fmt.Errorf("%w: %s discovery needs a region, and none could be read from the provider upstream",
				ErrInvalidRequest, entry.Name)
		}
		host = strings.ReplaceAll(host, catalog.RegionPlaceholder, region)
	}

	target := &url.URL{Scheme: "https", Host: host, Path: entry.Discovery.Path, RawQuery: entry.Discovery.Query}
	if err := c.checkPublicHost(target.Hostname()); err != nil {
		return "", err
	}
	return target.String(), nil
}

// regionFromUpstream recovers the region an operator embedded in the provider
// upstream, by matching it against the catalog's own host template. Bedrock's
// template is "bedrock-runtime.<region>.amazonaws.com" and Vertex's is
// "<region>-aiplatform.googleapis.com", so the region is whatever sits between
// the fixed halves. Returns empty when the upstream does not match the
// template, which is the case for a custom or proxied endpoint.
func regionFromUpstream(entry catalog.Provider, upstreamURL string) string {
	prefix, suffix, found := strings.Cut(entry.DefaultHost, catalog.RegionPlaceholder)
	if !found {
		return ""
	}
	parsed, err := url.Parse(strings.TrimSpace(upstreamURL))
	if err != nil {
		return ""
	}
	host := parsed.Hostname()
	if host == "" {
		// A bare host with no scheme parses as a path, not a host.
		host = strings.TrimSpace(upstreamURL)
	}
	// The two halves must not overlap. "bedrock-runtime.amazonaws.com" carries
	// both of Bedrock's — it is the regionless endpoint — and satisfies both
	// checks above while leaving nothing between them, so slicing it would
	// panic on an inverted range rather than report "no region here".
	if !strings.HasPrefix(host, prefix) || !strings.HasSuffix(host, suffix) ||
		len(host) < len(prefix)+len(suffix) {
		return ""
	}
	region := host[len(prefix) : len(host)-len(suffix)]
	if region == "" || strings.Contains(region, ".") {
		return ""
	}
	return region
}

// checkPublicHost refuses hosts that resolve to an address the management
// server should never be asked to reach on an operator's behalf.
func (c *Client) checkPublicHost(host string) error {
	if c.AllowPrivateHosts {
		return nil
	}
	if host == "" {
		return errors.New("discovery host is empty")
	}
	resolver := c.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	ctx, cancel := context.WithTimeout(context.Background(), fetchTimeout)
	defer cancel()

	addrs, err := resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return fmt.Errorf("resolve discovery host %q: %w", host, err)
	}
	// Every address must be public: a name that resolves to one public and one
	// loopback address is still a way to reach loopback.
	for _, addr := range addrs {
		if !isPublic(addr) {
			return fmt.Errorf("%w: discovery host %q resolves to a non-public address", ErrInvalidRequest, host)
		}
	}
	return nil
}

// isPublic reports whether an address is one we are willing to dial.
func isPublic(addr netip.Addr) bool {
	addr = addr.Unmap()
	switch {
	case !addr.IsValid(),
		addr.IsLoopback(),
		addr.IsPrivate(),
		addr.IsLinkLocalUnicast(),
		addr.IsLinkLocalMulticast(),
		addr.IsInterfaceLocalMulticast(),
		addr.IsMulticast(),
		addr.IsUnspecified():
		return false
	}
	// 100.64.0.0/10 (carrier NAT) is where NetBird's own overlay addresses
	// live, so it is emphatically not somewhere to send a provider credential.
	if addr.Is4() {
		b := addr.As4()
		if b[0] == 100 && b[1] >= 64 && b[1] <= 127 {
			return false
		}
	}
	return true
}

// applyAuth sets the credential header the catalog entry declares. A Vertex
// service-account key is exchanged for an OAuth token first, the same way the
// proxy does at request time.
func applyAuth(req *http.Request, entry catalog.Provider, apiKey string) error {
	key := strings.TrimSpace(apiKey)
	if key == "" {
		return fmt.Errorf("%w: %s discovery needs an API key", ErrInvalidRequest, entry.Name)
	}
	if rest, ok := strings.CutPrefix(key, vertexKeyfilePrefix); ok {
		token, err := mintGCPToken(req.Context(), rest)
		if err != nil {
			return err
		}
		key = token
	}
	name := entry.AuthHeaderName
	if name == "" {
		name = "Authorization"
	}
	template := entry.AuthHeaderTemplate
	if template == "" {
		template = "${API_KEY}"
	}
	req.Header.Set(name, strings.ReplaceAll(template, "${API_KEY}", key))
	return nil
}

// mintGCPToken exchanges a base64 service-account key for an access token.
func mintGCPToken(ctx context.Context, saKeyB64 string) (string, error) {
	jsonKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(saKeyB64))
	if err != nil {
		return "", fmt.Errorf("decode service-account key: %w", err)
	}
	conf, err := google.JWTConfigFromJSON(jsonKey, gcpScope)
	if err != nil {
		return "", fmt.Errorf("parse service-account key: %w", err)
	}
	tok, err := conf.TokenSource(ctx).Token()
	if err != nil {
		return "", fmt.Errorf("mint gcp token: %w", err)
	}
	return tok.AccessToken, nil
}

// decorate turns raw vendor ids into the models the caller renders, marking
// each with whether the shipped pricing table can price it.
func decorate(entry catalog.Provider, ids []listedModel) []Model {
	priced := make(map[string]struct{}, len(entry.Models))
	for _, m := range entry.Models {
		priced[m.ID] = struct{}{}
	}

	out := make([]Model, 0, len(ids))
	seen := make(map[string]struct{}, len(ids))
	for _, listed := range ids {
		if listed.id == "" {
			continue
		}
		if _, dup := seen[listed.id]; dup {
			continue
		}
		seen[listed.id] = struct{}{}

		// The catalog keys pricing by the normalised id while the vendor
		// issues the wire form, so normalise before asking whether we can
		// price it — otherwise every Bedrock profile would report unpriced.
		_, known := priced[normalizeForPricing(entry.ID, listed.id)]
		out = append(out, Model{ID: listed.id, Label: listed.label, PricingKnown: known})
	}
	return out
}

// refuseRedirect is the redirect policy every discovery request runs under. A
// redirect is a way to move the request to a host checkPublicHost never saw,
// so none are followed.
func refuseRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

func (c *Client) httpClient() *http.Client {
	if c.HTTPClient != nil {
		if c.HTTPClient.CheckRedirect != nil {
			return c.HTTPClient
		}
		// An injected client that states no policy still gets ours: the
		// no-redirect guarantee should not depend on the caller remembering it.
		//
		// Copied rather than assigned into: one Client is shared by every
		// request for the process's lifetime, so writing to its fields here
		// would race across request goroutines. The copy shares the Transport,
		// which is safe for concurrent use by design.
		clone := *c.HTTPClient
		clone.CheckRedirect = refuseRedirect
		return &clone
	}
	transport := guardedTransport
	if c.AllowPrivateHosts {
		transport = http.DefaultTransport
	}
	return &http.Client{
		Timeout:       fetchTimeout,
		Transport:     transport,
		CheckRedirect: refuseRedirect,
	}
}

// guardedTransport dials only addresses isPublic accepts.
//
// checkPublicHost resolves the host itself, and the transport then resolves it
// again when it dials — two lookups of a name whose owner chooses the answers.
// A record that returns a public address to the first and 127.0.0.1 to the
// second passes the guard and reaches loopback anyway, which is the whole of
// DNS rebinding. Re-checking at the socket closes that window: whatever the
// second lookup returned is what Control is handed, and an address the guard
// refuses never gets connected.
//
// Shared package-wide rather than built per Fetch so connections and their
// pool survive between calls; the guard holds no state.
var guardedTransport = newGuardedTransport()

func newGuardedTransport() http.RoundTripper {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		// Something replaced the default transport. Fall back to it rather
		// than dropping its behaviour, and rely on checkPublicHost alone.
		return http.DefaultTransport
	}
	// Cloned so proxy settings, TLS defaults and timeouts come from the
	// standard transport rather than being restated here.
	transport := base.Clone()
	dialer := &net.Dialer{
		Timeout:   fetchTimeout,
		KeepAlive: 30 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			return guardDialAddress(address)
		},
	}
	transport.DialContext = dialer.DialContext
	return transport
}

// guardDialAddress refuses a resolved socket address the discovery client has
// no business connecting to. Control hands it over post-resolution and
// pre-connect, once per address the dialer tries, so a name with several A
// records is checked at each one.
func guardDialAddress(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("discovery dial address %q is unreadable", address)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		// Control is documented to receive a resolved address; anything else
		// is a state we cannot vet, so it does not get dialled.
		return fmt.Errorf("discovery dial address %q is not an IP", host)
	}
	if !isPublic(addr) {
		return fmt.Errorf("discovery refused to dial non-public address %s", addr)
	}
	return nil
}
