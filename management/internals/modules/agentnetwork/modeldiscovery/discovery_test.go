package modeldiscovery

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/catalog"
	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/pricing"
)

// stubTransport answers every request with one canned response and records the
// request it was given, so a test can assert on the URL and headers the client
// built without a network round trip.
type stubTransport struct {
	status int
	body   string
	got    *http.Request
}

func (s *stubTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	s.got = req
	status := s.status
	if status == 0 {
		status = http.StatusOK
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(s.body)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Request:    req,
	}, nil
}

// newStubClient returns a client that never leaves the process. The host guard
// is disabled because it would otherwise resolve the vendor's real name, which
// would make these tests depend on DNS.
func newStubClient(status int, body string) (*Client, *stubTransport) {
	tr := &stubTransport{status: status, body: body}
	return &Client{
		HTTPClient:        &http.Client{Transport: tr},
		AllowPrivateHosts: true,
	}, tr
}

// The payloads below are trimmed from what the vendors actually returned in
// the discovery e2e, rather than invented, so a parser that only works against
// an idealised shape fails here.

const openAIListing = `{"object":"list","data":[
  {"id":"gpt-4o-mini","object":"model","created":1721172741,"owned_by":"system"},
  {"id":"gpt-4o","object":"model","created":1715367049,"owned_by":"system"}
]}`

const agentgatewayListing = `{"object":"list","data":[
  {"id":"gpt-4o-mini","object":"model","created":1785166485,"owned_by":"openai"},
  {"id":"claude-haiku-4-5","object":"model","created":1785166485,"owned_by":"anthropic"},
  {"id":"openai/*","object":"model","created":1785166485,"owned_by":"openai"},
  {"id":"*-latest","object":"model","created":1785166485,"owned_by":"openai"}
]}`

const anthropicListing = `{"data":[
  {"type":"model","id":"claude-haiku-4-5-20251001","display_name":"Claude Haiku 4.5"},
  {"type":"model","id":"claude-sonnet-4-6","display_name":"Claude Sonnet 4.6"}
],"has_more":false}`

const bedrockListing = `{"inferenceProfileSummaries":[
  {"inferenceProfileId":"eu.anthropic.claude-haiku-4-5-20251001-v1:0",
   "inferenceProfileName":"EU Anthropic Claude Haiku 4.5","status":"ACTIVE","type":"SYSTEM_DEFINED"},
  {"inferenceProfileId":"global.cohere.embed-v4:0",
   "inferenceProfileName":"Global Cohere Embed v4","status":"ACTIVE","type":"SYSTEM_DEFINED"},
  {"inferenceProfileId":"eu.meta.llama3-2-1b-instruct-v1:0",
   "inferenceProfileName":"EU Meta Llama 3.2 1B","status":"INACTIVE","type":"SYSTEM_DEFINED"}
]}`

const vertexListing = `{"publisherModels":[
  {"name":"publishers/anthropic/models/claude-3-opus","versionId":"20240229","launchStage":"GA"},
  {"name":"publishers/anthropic/models/claude-sonnet-4-5","versionId":"20250929","launchStage":"GA"}
]}`

func TestFetchOpenAIListing(t *testing.T) {
	cl, tr := newStubClient(http.StatusOK, openAIListing)

	models, err := cl.Fetch(context.Background(), Request{
		CatalogID:   "openai_api",
		UpstreamURL: "https://api.openai.com",
		APIKey:      "sk-test",
	})
	require.NoError(t, err)

	assert.Equal(t, "https://api.openai.com/v1/models", tr.got.URL.String())
	assert.Equal(t, "Bearer sk-test", tr.got.Header.Get("Authorization"),
		"the credential must be injected through the catalog's auth template")
	assert.Equal(t, []string{"gpt-4o-mini", "gpt-4o"}, ids(models))
	for _, m := range models {
		assert.True(t, m.PricingKnown, "both models are in the shipped catalog: %s", m.ID)
	}
}

func TestFetchAgentgatewayListing(t *testing.T) {
	cl, tr := newStubClient(http.StatusOK, agentgatewayListing)

	models, err := cl.Fetch(context.Background(), Request{
		CatalogID:   "agentgateway",
		UpstreamURL: "https://gateway.example.com",
		APIKey:      "virtual-key",
	})
	require.NoError(t, err)

	assert.Equal(t, "https://gateway.example.com/v1/models", tr.got.URL.String())
	assert.Equal(t, "Bearer virtual-key", tr.got.Header.Get("Authorization"),
		"agentgateway model discovery must use the configured virtual key")
	assert.Equal(t, []string{"gpt-4o-mini", "claude-haiku-4-5"}, ids(models),
		"model patterns must not be offered as exact NetBird authorization rows")
	for _, m := range models {
		assert.True(t, m.PricingKnown, "known upstream model must use NetBird catalog pricing: %s", m.ID)
	}
}

func TestFetchAnthropicSendsTheVersionHeader(t *testing.T) {
	cl, tr := newStubClient(http.StatusOK, anthropicListing)

	models, err := cl.Fetch(context.Background(), Request{
		CatalogID:   "anthropic_api",
		UpstreamURL: "https://api.anthropic.com",
		APIKey:      "sk-ant-test",
	})
	require.NoError(t, err)

	// Anthropic rejects a request without the version header, so a listing
	// that reached us at all proves it was sent — but assert it, because the
	// failure mode otherwise only shows up against the live API.
	assert.Equal(t, "2023-06-01", tr.got.Header.Get("anthropic-version"))
	assert.Equal(t, "sk-ant-test", tr.got.Header.Get("x-api-key"),
		"Anthropic takes a bare key under its own header, not a Bearer token")
	assert.Equal(t, "limit=1000", tr.got.URL.RawQuery)

	assert.Equal(t, []string{"claude-haiku-4-5-20251001", "claude-sonnet-4-6"}, ids(models))
	assert.Equal(t, "Claude Haiku 4.5", models[0].Label)
}

func TestFetchBedrockUsesTheControlPlaneAndKeepsWireIDs(t *testing.T) {
	cl, tr := newStubClient(http.StatusOK, bedrockListing)

	models, err := cl.Fetch(context.Background(), Request{
		CatalogID: "bedrock_api",
		// The record's upstream is the RUNTIME host, which does not serve
		// listings. The catalog's own discovery host must win over it.
		UpstreamURL: "https://bedrock-runtime.eu-central-1.amazonaws.com",
		Region:      "eu-central-1",
		APIKey:      "aws-bearer",
	})
	require.NoError(t, err)

	assert.Equal(t, "https://bedrock.eu-central-1.amazonaws.com/inference-profiles",
		tr.got.URL.String(), "listings come from the control plane, not the runtime host")

	// Region-prefixed ids verbatim: the prefix is what makes them invocable
	// and it cannot be reconstructed — global.* alongside eu.* is exactly the
	// case that defeats deriving it from the configured region.
	assert.Equal(t, []string{
		"eu.anthropic.claude-haiku-4-5-20251001-v1:0",
		"global.cohere.embed-v4:0",
	}, ids(models), "an INACTIVE profile must not be offered")

	assert.True(t, models[0].PricingKnown,
		"the catalog prices anthropic.claude-haiku-4-5, which this id normalises to")
	assert.False(t, models[1].PricingKnown,
		"cohere embed is not in the shipped Bedrock catalog, so the operator must price it")

	// The rates travel with the model, so the form can prefill an editable row
	// rather than making the operator look every price up by hand.
	assert.Positive(t, models[0].InputPer1k, "a priced model must carry its input rate")
	assert.Positive(t, models[0].OutputPer1k, "a priced model must carry its output rate")
	// An unpriced model is offered at zero and flagged, not withheld: the
	// vendor says the credential can reach it.
	assert.Zero(t, models[1].InputPer1k)
	assert.Zero(t, models[1].OutputPer1k)
}

// TestDiscoveredRatesMatchTheCatalogEndpoint pins the two prefill paths to one
// table. The provider form fills a model row either from the catalog response
// or from a discovery response, and an operator who switches between them must
// not see the price change — both must equal what the proxy will bill.
func TestDiscoveredRatesMatchTheCatalogEndpoint(t *testing.T) {
	cl, _ := newStubClient(http.StatusOK, openAIListing)

	models, err := cl.Fetch(context.Background(), Request{
		CatalogID:   "openai_api",
		UpstreamURL: "https://api.openai.com",
		APIKey:      "sk-test",
	})
	require.NoError(t, err)
	require.NotEmpty(t, models)

	entry, ok := catalog.Lookup("openai_api")
	require.True(t, ok)

	for _, m := range models {
		want, known := pricing.LookupDefault(entry.PricingSurfaces, m.ID)
		require.True(t, known, "%s should be priced by the default table", m.ID)
		assert.Equal(t, want.InputPer1k, m.InputPer1k, "input rate for %s", m.ID)
		assert.Equal(t, want.OutputPer1k, m.OutputPer1k, "output rate for %s", m.ID)
		assert.Equal(t, want.CachedInputPer1k, m.CachedInputPer1k, "cached-input rate for %s", m.ID)
	}
}

func TestFetchVertexJoinsNameAndVersion(t *testing.T) {
	cl, _ := newStubClient(http.StatusOK, vertexListing)

	models, err := cl.Fetch(context.Background(), Request{
		CatalogID:   "vertex_ai_api",
		UpstreamURL: "https://us-east5-aiplatform.googleapis.com",
		Region:      "us-east5",
		APIKey:      "ya29.test-token",
	})
	require.NoError(t, err)

	// Vertex addresses a model as "<id>@<version>" on rawPredict, and splits
	// those across two fields in the listing.
	assert.Equal(t, []string{"claude-3-opus@20240229", "claude-sonnet-4-5@20250929"}, ids(models))
	assert.Equal(t, "claude-3-opus", models[0].Label)
}

func TestFetchSurfacesTheVendorStatus(t *testing.T) {
	cl, _ := newStubClient(http.StatusForbidden, `{"error":{"message":"no access"}}`)

	_, err := cl.Fetch(context.Background(), Request{
		CatalogID:   "openai_api",
		UpstreamURL: "https://api.openai.com",
		APIKey:      "sk-test",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403",
		"an operator whose key lacks access needs to see which status the vendor returned")
}

func TestFetchRejectsAProviderWithoutDiscovery(t *testing.T) {
	cl, _ := newStubClient(http.StatusOK, openAIListing)

	_, err := cl.Fetch(context.Background(), Request{
		CatalogID:   "litellm_proxy",
		UpstreamURL: "https://gateway.example.com",
		APIKey:      "sk-test",
	})
	assert.ErrorIs(t, err, ErrNoDiscovery,
		"a gateway with no listing endpoint must be distinguishable from a failure, so the caller can fall back")
}

func TestFetchRequiresACredential(t *testing.T) {
	cl, _ := newStubClient(http.StatusOK, openAIListing)

	_, err := cl.Fetch(context.Background(), Request{
		CatalogID:   "openai_api",
		UpstreamURL: "https://api.openai.com",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "API key")
}

func TestDiscoveryURLNeedsARegionWhenTheHostTemplatesOne(t *testing.T) {
	cl, _ := newStubClient(http.StatusOK, bedrockListing)

	// An upstream that matches no catalog template — a proxy in front of
	// Bedrock, say — leaves nothing to read the region from. Refusing beats
	// guessing: an unsubstituted placeholder would dial a host that does not
	// exist, and a guessed region would dial the wrong account's endpoint.
	_, err := cl.Fetch(context.Background(), Request{
		CatalogID:   "bedrock_api",
		UpstreamURL: "https://bedrock.internal-proxy.example.com",
		APIKey:      "aws-bearer",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "region")
}

// TestHostGuardRejectsNonPublicAddresses is the SSRF guard. Management holds a
// credential for every provider, so an upstream pointed at an internal address
// would turn discovery into a way to probe — and hand a token to — the
// management server's own network.
func TestHostGuardRejectsNonPublicAddresses(t *testing.T) {
	for _, tc := range []struct {
		name string
		addr string
		want bool
	}{
		{"loopback v4", "127.0.0.1", false},
		{"loopback v6", "::1", false},
		{"private 10/8", "10.0.0.5", false},
		{"private 172.16/12", "172.16.4.1", false},
		{"private 192.168/16", "192.168.1.1", false},
		{"link-local", "169.254.169.254", false}, // cloud metadata
		{"unspecified", "0.0.0.0", false},
		{"multicast", "224.0.0.1", false},
		{"netbird overlay 100.64/10", "100.90.1.2", false},
		{"v4-mapped loopback", "::ffff:127.0.0.1", false},
		{"public v4", "1.1.1.1", true},
		{"public v6", "2606:4700:4700::1111", true},
		{"just outside CGNAT", "100.128.0.1", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, err := netip.ParseAddr(tc.addr)
			require.NoError(t, err)
			assert.Equal(t, tc.want, isPublic(addr))
		})
	}
}

func TestHostGuardResolvesAndRejectsLocalhost(t *testing.T) {
	cl := &Client{}
	err := cl.checkPublicHost(context.Background(), "localhost")
	require.Error(t, err, "a name resolving to loopback must be refused, not just a literal address")
	assert.Contains(t, err.Error(), "non-public")
}

// TestRedirectsAreNotFollowed covers a gap the other tests leave open: they all
// inject an HTTPClient, which bypasses httpClient() and therefore the redirect
// policy entirely. The policy is a security control — a 302 moves the request
// to a host checkPublicHost never resolved — so it needs a test that goes
// through the constructor the manager actually uses.
func TestRedirectsAreNotFollowed(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	for name, cl := range map[string]*Client{
		// The production shape: no injected client at all.
		"default client": {AllowPrivateHosts: true},
		// An injected client that states no policy must inherit ours rather
		// than silently chasing the redirect.
		"injected client with no policy": {
			AllowPrivateHosts: true,
			HTTPClient:        &http.Client{},
		},
	} {
		t.Run(name, func(t *testing.T) {
			hits = 0
			req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
			require.NoError(t, err)

			resp, err := cl.httpClient().Do(req)
			require.NoError(t, err)
			t.Cleanup(func() { _ = resp.Body.Close() })

			assert.Equal(t, http.StatusFound, resp.StatusCode,
				"the redirect must be surfaced, not followed to an unchecked host")
			assert.Equal(t, 1, hits, "exactly one request must leave the client")
		})
	}
}

// TestInjectedClientKeepsItsOwnRedirectPolicy pins that the default above is a
// default, not an override, and that supplying it does not mutate the caller's
// client — one Client is shared across every request, so a write here would
// race.
func TestInjectedClientKeepsItsOwnRedirectPolicy(t *testing.T) {
	own := func(*http.Request, []*http.Request) error { return nil }
	injected := &http.Client{CheckRedirect: own}
	cl := &Client{HTTPClient: injected}

	assert.Same(t, injected, cl.httpClient(),
		"a client that states a policy must be handed back untouched")

	bare := &http.Client{}
	cl = &Client{HTTPClient: bare}
	require.NotSame(t, bare, cl.httpClient(), "the policy must be applied to a copy")
	assert.Nil(t, bare.CheckRedirect, "the caller's client must not be written to")
}

// TestDialGuardRejectsRebindingToANonPublicAddress covers the window between
// the two DNS lookups. checkPublicHost resolves the host, then the transport
// resolves it again to dial; a name whose owner answers the first with a public
// address and the second with 127.0.0.1 would otherwise pass the guard and
// still reach loopback. The dial-time check sees whatever the second lookup
// actually returned.
func TestDialGuardRejectsRebindingToANonPublicAddress(t *testing.T) {
	for _, tc := range []struct {
		name    string
		address string
		wantErr string
	}{
		{"loopback", "127.0.0.1:443", "non-public"},
		{"cloud metadata", "169.254.169.254:80", "non-public"},
		{"rfc1918", "10.1.2.3:443", "non-public"},
		{"netbird overlay", "100.90.1.2:443", "non-public"},
		{"loopback v6", "[::1]:443", "non-public"},
		{"unresolved name", "evil.example.com:443", "not an IP"},
		{"no port", "1.1.1.1", "unreadable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := guardDialAddress(tc.address)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}

	assert.NoError(t, guardDialAddress("1.1.1.1:443"), "a public address must still be dialled")
	assert.NoError(t, guardDialAddress("[2606:4700:4700::1111]:443"))
}

// TestDialGuardIsInstalledOnTheDefaultClient pins the wiring rather than the
// guard: a correct guard nothing calls protects nothing.
func TestDialGuardIsInstalledOnTheDefaultClient(t *testing.T) {
	cl := &Client{}
	transport, ok := cl.httpClient().Transport.(*http.Transport)
	require.True(t, ok, "the default discovery client must carry the guarded transport")
	require.NotNil(t, transport.DialContext, "the guarded transport must dial through the guard")

	_, err := transport.DialContext(context.Background(), "tcp", "127.0.0.1:9")
	require.Error(t, err, "the guard must refuse loopback even when the caller dials it directly")
	assert.Contains(t, err.Error(), "non-public")

	// Tests point the client at a loopback server on purpose, so the opt-out
	// has to reach the dialer too.
	relaxed := &Client{AllowPrivateHosts: true}
	assert.Equal(t, http.DefaultTransport, relaxed.httpClient().Transport)
}

// TestCallerInputFailuresAreMarkedInvalid keeps the handler's 400 mapping
// honest: it branches on this sentinel, so an unmarked caller-input failure
// silently becomes a 500.
func TestCallerInputFailuresAreMarkedInvalid(t *testing.T) {
	for _, tc := range []struct {
		name string
		req  Request
	}{
		{"unknown provider", Request{CatalogID: "not_a_provider", APIKey: "k"}},
		{"unusable upstream", Request{CatalogID: "openai_api", UpstreamURL: "://", APIKey: "k"}},
		{"missing api key", Request{CatalogID: "openai_api", UpstreamURL: "https://api.openai.com"}},
		{"no region to read", Request{
			CatalogID:   "bedrock_api",
			UpstreamURL: "https://bedrock-runtime.amazonaws.com",
			APIKey:      "aws-bearer",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cl, _ := newStubClient(http.StatusOK, openAIListing)
			_, err := cl.Fetch(context.Background(), tc.req)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidRequest)
		})
	}
}

// TestEveryDiscoveryEntryHasAParser keeps the catalog and the parser table from
// drifting: adding a Discovery block with a shape nothing parses would fail
// only at runtime, in front of an operator.
func TestEveryDiscoveryEntryHasAParser(t *testing.T) {
	for _, entry := range catalog.All() {
		if entry.Discovery == nil {
			continue
		}
		t.Run(entry.ID, func(t *testing.T) {
			assert.NotEmpty(t, entry.Discovery.Path, "a discovery entry needs a path")
			_, err := parseListing(entry.Discovery.Shape, []byte(`{}`))
			assert.NoError(t, err, "shape %q has no parser", entry.Discovery.Shape)
		})
	}
}

func ids(models []Model) []string {
	out := make([]string, 0, len(models))
	for _, m := range models {
		out = append(out, m.ID)
	}
	return out
}

// TestRegionIsReadBackFromTheUpstream covers the reason the API takes no
// region field: a provider record has none, and the operator already encoded
// it in the upstream host when they configured inference.
func TestRegionIsReadBackFromTheUpstream(t *testing.T) {
	cl, tr := newStubClient(http.StatusOK, bedrockListing)

	_, err := cl.Fetch(context.Background(), Request{
		CatalogID:   "bedrock_api",
		UpstreamURL: "https://bedrock-runtime.us-west-2.amazonaws.com",
		APIKey:      "aws-bearer",
	})
	require.NoError(t, err)
	assert.Equal(t, "bedrock.us-west-2.amazonaws.com", tr.got.URL.Host)
}

func TestRegionFromUpstream(t *testing.T) {
	bedrock, ok := catalog.Lookup("bedrock_api")
	require.True(t, ok)
	vertex, ok := catalog.Lookup("vertex_ai_api")
	require.True(t, ok)

	for _, tc := range []struct {
		name     string
		entry    catalog.Provider
		upstream string
		want     string
	}{
		{"bedrock runtime host", bedrock, "https://bedrock-runtime.eu-central-1.amazonaws.com", "eu-central-1"},
		{"bedrock without scheme", bedrock, "bedrock-runtime.ap-south-1.amazonaws.com", "ap-south-1"},
		{"vertex regional host", vertex, "https://us-east5-aiplatform.googleapis.com", "us-east5"},
		// A proxied or self-hosted upstream matches no template, and guessing
		// a region from it would build a URL pointing somewhere arbitrary.
		{"unrelated upstream", bedrock, "https://llm.internal.example.com", ""},
		{"vertex global host has no region segment", vertex, "https://aiplatform.googleapis.com", ""},
		// Bedrock's regionless endpoint carries both halves of the template at
		// once, with nothing between them. It has to read as "no region here"
		// rather than as an inverted slice range.
		{"bedrock regionless endpoint", bedrock, "https://bedrock-runtime.amazonaws.com", ""},
		{"bedrock regionless without scheme", bedrock, "bedrock-runtime.amazonaws.com", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, RegionFromUpstream(tc.entry, tc.upstream))
		})
	}
}

// bedrockGeoListing carries profiles from geographies the original prefix list
// did not name. Every one reduces to a catalog key, so every one must arrive
// priced — an unstripped geography is what made a real account's listing come
// back almost entirely at zero.
const bedrockGeoListing = `{"inferenceProfileSummaries":[
  {"inferenceProfileId":"jp.anthropic.claude-sonnet-5-20260514-v1:0",
   "inferenceProfileName":"JP Anthropic Claude Sonnet 5","status":"ACTIVE","type":"SYSTEM_DEFINED"},
  {"inferenceProfileId":"au.anthropic.claude-haiku-4-5-20251001-v1:0",
   "inferenceProfileName":"AU Anthropic Claude Haiku 4.5","status":"ACTIVE","type":"SYSTEM_DEFINED"},
  {"inferenceProfileId":"us-gov.anthropic.claude-sonnet-5-20260514-v1:0",
   "inferenceProfileName":"GovCloud Anthropic Claude Sonnet 5","status":"ACTIVE","type":"SYSTEM_DEFINED"}
]}`

func TestBedrockProfilesFromAnyGeographyArrivePriced(t *testing.T) {
	cl, _ := newStubClient(http.StatusOK, bedrockGeoListing)

	models, err := cl.Fetch(context.Background(), Request{
		CatalogID:   "bedrock_api",
		UpstreamURL: "https://bedrock-runtime.eu-central-1.amazonaws.com",
		APIKey:      "aws-token",
	})
	require.NoError(t, err)
	require.Len(t, models, 3)

	for _, m := range models {
		assert.True(t, m.PricingKnown, "%s must resolve to a catalog rate", m.ID)
		assert.Greater(t, m.InputPer1k, 0.0, "input rate for %s", m.ID)
		assert.Greater(t, m.OutputPer1k, 0.0, "output rate for %s", m.ID)
		assert.Greater(t, m.CacheReadPer1k, 0.0, "cache-read rate for %s", m.ID)
	}

	// The wire id is preserved whatever the pricing key reduced to: it is the
	// only form that works at invoke time.
	assert.Equal(t, "jp.anthropic.claude-sonnet-5-20260514-v1:0", models[0].ID)
}

// TestFetch_AHostThatWillNotResolveIsUnreachable closes a gap the live suite
// found. The SSRF guard resolves the host before any request is built, so a
// name that does not resolve fails there rather than at the transport — and
// that error used to reach the caller unclassified. A wrong hostname is the
// commonest way for an upstream to be wrong, so it has to arrive as
// "unreachable" and not as an unrecognised fault.
func TestFetch_AHostThatWillNotResolveIsUnreachable(t *testing.T) {
	// A resolver whose dial always fails, so the lookup errors without the
	// test depending on real DNS.
	refusing := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, errors.New("resolver unavailable")
		},
	}
	client := &Client{Resolver: refusing}

	_, err := client.Fetch(context.Background(), Request{
		CatalogID:   "openai_api",
		UpstreamURL: "https://not-a-real-vendor-host.example.invalid",
		APIKey:      "sk-test",
	})

	require.Error(t, err)
	var unreachable *UnreachableError
	require.ErrorAs(t, err, &unreachable, "a host that will not resolve must classify as unreachable")
	require.NotErrorIs(t, err, ErrPrivateHost, "it is not a host we declined to dial")
}

// TestFetch_AProxyInThePathDoesNotSilentlyDisableTheCheck pins a fail-open the
// dial-time guard can produce. checkPublicHost clears the target before
// anything is dialled, so a private address refused at the socket is never the
// operator's upstream — it is a rebinding attempt, or an HTTP proxy the
// management server egresses through. Reporting either as ErrPrivateHost would
// read as "this provider cannot be checked" and let every save through
// unchecked, which is how a proxied deployment would install this feature and
// have it quietly do nothing.
func TestFetch_AProxyInThePathDoesNotSilentlyDisableTheCheck(t *testing.T) {
	// A transport that refuses at the socket exactly as the guard does, with a
	// loopback address standing in for the proxy the dial went to.
	// AllowPrivateHosts short-circuits the resolve-stage check only; the
	// injected transport below is still what the request goes through. Without
	// it this test resolves api.openai.com for real, and on a runner with no
	// egress that lookup fails as an UnreachableError too — so it would pass
	// while never reaching the socket guard it is named for.
	client := &Client{AllowPrivateHosts: true, HTTPClient: &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, guardDialAddress("127.0.0.1:38599")
		}),
		CheckRedirect: refuseRedirect,
	}}

	_, err := client.Fetch(context.Background(), Request{
		CatalogID:   "openai_api",
		UpstreamURL: "https://api.openai.com",
		APIKey:      "sk-test",
	})

	require.Error(t, err)
	require.NotErrorIs(t, err, ErrPrivateHost,
		"a refusal at the socket must not read as an upstream we cannot check")
	var unreachable *UnreachableError
	require.ErrorAs(t, err, &unreachable, "it is the vendor we failed to reach")
}

// roundTripFunc adapts a function to http.RoundTripper.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestFetch_TheUpstreamIsCheckedWhenTheListingCannotVouchForIt covers the hole
// a separate listing host leaves. Bedrock lists from the control plane, so a
// record whose runtime upstream does not exist reaches a perfectly good
// listing and saves — the requests it then serves go nowhere.
//
// Both halves matter. A runtime host that cannot be resolved is the record
// being wrong, and blocks. A proxied one resolves and only leaves the region
// underivable, which stays the unverifiable outcome it already was.
func TestFetch_TheUpstreamIsCheckedWhenTheListingCannotVouchForIt(t *testing.T) {
	refusing := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, errors.New("resolver unavailable")
		},
	}
	client := &Client{Resolver: refusing}

	_, err := client.Fetch(context.Background(), Request{
		CatalogID: "bedrock_api",
		// Matches no catalog template, so nothing here reaches the control
		// plane the listing comes from: without its own check this upstream
		// was never contacted at all.
		UpstreamURL: "https://bedrock.typo.example.invalid",
		APIKey:      "aws-bearer",
	})

	require.Error(t, err)
	var unreachable *UnreachableError
	require.ErrorAs(t, err, &unreachable, "a runtime host that will not resolve must block the save")
}

// TestFetch_AListingHostOfItsOwnDoesNotReachThroughTheUpstream keeps the check
// above from reading the operator's upstream as the place to list from.
func TestFetch_AListingHostOfItsOwnDoesNotReachThroughTheUpstream(t *testing.T) {
	cl, tr := newStubClient(http.StatusOK, bedrockListing)

	_, err := cl.Fetch(context.Background(), Request{
		CatalogID:   "bedrock_api",
		UpstreamURL: "https://bedrock-runtime.eu-central-1.amazonaws.com",
		APIKey:      "aws-bearer",
	})
	require.NoError(t, err)

	assert.Equal(t, "bedrock.eu-central-1.amazonaws.com", tr.got.URL.Host,
		"checking the runtime host must not turn it into the listing host")
}
