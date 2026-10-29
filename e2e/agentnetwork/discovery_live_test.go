//go:build e2e

package agentnetwork

import (
	"context"
	"encoding/json"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/e2e/harness"
	sharedllm "github.com/netbirdio/netbird/shared/llm"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

// TestLiveModelDiscovery drives model discovery against the REAL vendor
// endpoints — OpenAI, Anthropic, Bedrock and Vertex — rather than the mock.
//
// The mock upstream proves the filter's mechanics: it advertises ids we chose,
// so a listing narrowing to the ones we authorised is arithmetic we already
// controlled both sides of. What it cannot prove is that the filter survives
// contact with a real catalogue — ids we never enumerated, dated builds whose
// suffix the vendor picks, surfaces that answer a listing request with
// something other than a listing. That is what this covers, and it is the part
// a QA engineer would otherwise have to walk through by hand.
//
// One proxy serves every case. Each provider gets its own group, policy and
// client, because a model-less request matches exactly ONE route
// (matchModelless): with two providers authorised for the same caller, the
// listing would go to whichever won the tiebreak and the other would go
// untested. Group-scoping the caller makes each provider the only candidate
// for its own client.
func TestLiveModelDiscovery(t *testing.T) {
	cases := liveDiscoveryCases()
	if len(cases) == 0 {
		t.Skip("no provider keys set; source ~/.llm-keys to run live model discovery")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	t.Logf("[discovery] live matrix: %s", strings.Join(caseNames(cases), ", "))

	// Provision every provider, group and policy before the proxy starts: the
	// proxy takes a configuration snapshot at connect time and does not
	// reconcile provider changes made afterwards.
	keys := make(map[string]string, len(cases))
	for i := range cases {
		keys[cases[i].name] = provisionLiveDiscovery(t, ctx, &cases[i])
	}

	endpoint, firstIP, firstClient, px := connectClient(t, ctx, "disc-live", keys[cases[0].name])
	clients := map[string]*harness.Client{cases[0].name: firstClient}
	ips := map[string]string{cases[0].name: firstIP}
	for _, tc := range cases[1:] {
		cl := joinClient(t, ctx, px, endpoint, keys[tc.name])
		ip, err := cl.ResolveProxyIP(ctx, endpoint)
		require.NoError(t, err, "resolve endpoint from the %s client", tc.name)
		clients[tc.name] = cl
		ips[tc.name] = ip
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runLiveDiscoveryCase(t, ctx, tc, clients[tc.name], endpoint, ips[tc.name])
		})
	}
}

// discoveryOutcome is what a discovery request must produce end to end. The
// three are genuinely different contracts, not degrees of success: only the
// first puts a bounded listing in front of the caller.
type discoveryOutcome int

const (
	// outcomeFiltered: the proxy routes the request and bounds the response to
	// what the caller may use.
	outcomeFiltered discoveryOutcome = iota
	// outcomeDenied: no provider of this shape can serve the surface, so the
	// proxy refuses rather than rewriting the request onto an upstream that
	// would 404 it. The caller gets a NetBird error, not a vendor one.
	outcomeDenied
	// outcomeUpstreamNoListing: the proxy routes the request to the configured
	// upstream, and the vendor does not implement the endpoint there. Proxy
	// side correct, product side a dead end — see the Bedrock case.
	outcomeUpstreamNoListing
)

// liveDiscoveryCase is one provider's discovery surface and what the proxy
// must make of it.
type liveDiscoveryCase struct {
	name      string
	catalogID string
	upstream  string
	apiKey    string

	// path is the discovery endpoint the client calls. Not every surface uses
	// /v1/models: Bedrock lists inference profiles instead.
	path string
	// headers the vendor requires on a bare GET (Anthropic versions its API
	// through a header, and rejects a request without one).
	headers []string

	// models the provider record enumerates. Empty models a gateway record,
	// which enumerates nothing and claims everything.
	models []string
	// allowlist, when non-empty, is a guardrail narrowing the policy below the
	// provider's own enumeration — the second of the two bounds discovery
	// applies, and the only one a provider record alone cannot demonstrate.
	allowlist []string

	// outcome is what this surface must produce end to end.
	outcome discoveryOutcome

	// permitted is every id allowed to survive filtering, in the form the
	// provider record registers it. A surviving id counts as permitted when it
	// matches one of these outright or after Anthropic date-normalisation.
	permitted []string
	// wantHidden are ids the upstream is known to advertise and the bound must
	// remove. Only set where we enumerate the model ourselves, so the
	// expectation cannot rot when a vendor changes its catalogue.
	wantHidden []string
}

// liveDiscoveryCases builds the matrix from whichever provider credentials are
// present, mirroring availableProviders' env-var gating so a partial key set
// still yields partial coverage.
func liveDiscoveryCases() []liveDiscoveryCase {
	var cases []liveDiscoveryCase

	// OpenAI enumerates TWO real models and the policy permits one. That is
	// the only case here where both bounds are observable at once: the
	// upstream advertises dozens of ids, the provider record cuts them to two,
	// and the guardrail cuts those to one.
	if k := os.Getenv("OPENAI_TOKEN"); k != "" {
		cases = append(cases, liveDiscoveryCase{
			name: "openai", catalogID: "openai_api", upstream: "https://api.openai.com", apiKey: k,
			path:       "/v1/models",
			models:     []string{"gpt-4o-mini", "gpt-4o"},
			allowlist:  []string{"gpt-4o-mini"},
			outcome:    outcomeFiltered,
			permitted:  []string{"gpt-4o-mini"},
			wantHidden: []string{"gpt-4o"},
		})
	}

	// Anthropic is the surface Claude Code actually calls. Its listing returns
	// DATED build ids (claude-haiku-4-5-20251001) while the provider record
	// registers the undated id, so this is the case that proves the filter's
	// date-normalisation against ids the vendor chose rather than ids we wrote.
	if k := os.Getenv("ANTHROPIC_TOKEN"); k != "" {
		cases = append(cases, liveDiscoveryCase{
			name: "anthropic", catalogID: "anthropic_api", upstream: "https://api.anthropic.com", apiKey: k,
			path:      "/v1/models",
			headers:   []string{"anthropic-version: 2023-06-01"},
			models:    []string{"claude-haiku-4-5"},
			outcome:   outcomeFiltered,
			permitted: []string{"claude-haiku-4-5"},
		})
	}

	// Bedrock lists inference profiles, not models: matchModelless routes
	// /inference-profiles to a Bedrock route and refuses /v1/models for one.
	//
	// The listing is served by the CONTROL PLANE (bedrock.<region>), not the
	// runtime host a provider record must point at for InvokeModel — the
	// runtime host answers <UnknownOperationException/>. The router now sends
	// the listing, and only the listing, to the control plane, so this case
	// asserts a real filtered listing rather than the 404 it used to get.
	//
	// The mock upstream cannot show any of this: it answers
	// /inference-profiles on the same listener as everything else, so a
	// mock-based test passes whichever host the request went to.
	if k := os.Getenv("AWS_BEARER_TOKEN_BEDROCK"); k != "" {
		region := os.Getenv("AWS_REGION")
		if region == "" {
			region = "eu-central-1"
		}
		model := os.Getenv("AWS_BEDROCK_MODEL")
		if model == "" {
			model = "global.anthropic.claude-sonnet-4-6"
		}
		cases = append(cases, liveDiscoveryCase{
			name: "bedrock", catalogID: "bedrock_api",
			upstream: "https://bedrock-runtime." + region + ".amazonaws.com", apiKey: k,
			path: "/inference-profiles",
			// Registered verbatim, as an operator would copy it from AWS: the
			// region prefix is what makes the id invocable, and the listing
			// returns ids in exactly this form.
			models:    []string{model},
			outcome:   outcomeFiltered,
			permitted: []string{model},
		})
	}

	// Vertex carries the model in the rawPredict path and serves no listing
	// endpoint at all, so the proxy must refuse discovery rather than rewrite
	// it onto an upstream that would 404.
	if sa := os.Getenv("GOOGLE_VERTEX_SA_BASE64"); sa != "" {
		if project := os.Getenv("GOOGLE_VERTEX_PROJECT"); project != "" {
			region := os.Getenv("GOOGLE_VERTEX_REGION")
			if region == "" {
				region = "global"
			}
			host := "aiplatform.googleapis.com"
			if region != "global" {
				host = region + "-aiplatform.googleapis.com"
			}
			cases = append(cases, liveDiscoveryCase{
				name: "vertex", catalogID: "vertex_ai_api", upstream: "https://" + host,
				apiKey:  "keyfile::" + sa,
				path:    "/v1/models",
				outcome: outcomeDenied,
			})
		}
	}

	return cases
}

// provisionLiveDiscovery creates the group, provider, optional guardrail and
// policy for one case, and returns the setup key a client joins that group
// with. Scoping each provider to its own group is what keeps it the only
// candidate for its own client's model-less request.
func provisionLiveDiscovery(t *testing.T, ctx context.Context, tc *liveDiscoveryCase) string {
	t.Helper()

	grp, err := srv.API().Groups.Create(ctx, api.PostApiGroupsJSONRequestBody{Name: "e2e-disc-live-" + tc.name})
	require.NoError(t, err, "create group for %s", tc.name)
	t.Cleanup(func() { _ = srv.API().Groups.Delete(context.Background(), grp.Id) })

	ephemeral := false
	sk, err := srv.API().SetupKeys.Create(ctx, api.PostApiSetupKeysJSONRequestBody{
		Name:       "e2e-disc-live-" + tc.name,
		Type:       "reusable",
		ExpiresIn:  86400,
		UsageLimit: 0,
		AutoGroups: []string{grp.Id},
		Ephemeral:  &ephemeral,
	})
	require.NoError(t, err, "mint setup key for %s", tc.name)
	require.NotEmpty(t, sk.Key, "setup key plaintext for %s", tc.name)

	req := api.AgentNetworkProviderRequest{
		Name:        "e2e-disc-live-" + tc.name,
		ProviderId:  tc.catalogID,
		UpstreamUrl: tc.upstream,
		ApiKey:      &tc.apiKey,
		Enabled:     ptr(true),
	}
	if len(tc.models) > 0 {
		models := make([]api.AgentNetworkProviderModel, 0, len(tc.models))
		for _, id := range tc.models {
			models = append(models, api.AgentNetworkProviderModel{Id: id, InputPer1k: 0.001, OutputPer1k: 0.002})
		}
		req.Models = &models
	}
	prov, err := srv.CreateProvider(ctx, req)
	require.NoError(t, err, "create provider %s", tc.name)
	t.Cleanup(func() { _ = srv.DeleteProvider(context.Background(), prov.Id) })

	polReq := api.AgentNetworkPolicyRequest{
		Name:                   "e2e-disc-live-" + tc.name,
		Enabled:                ptr(true),
		SourceGroups:           []string{grp.Id},
		DestinationProviderIds: []string{prov.Id},
	}
	if len(tc.allowlist) > 0 {
		var gr api.AgentNetworkGuardrailRequest
		gr.Name = "e2e-disc-live-" + tc.name
		gr.Checks.ModelAllowlist.Enabled = true
		gr.Checks.ModelAllowlist.Models = tc.allowlist
		g, gerr := srv.CreateGuardrail(ctx, gr)
		require.NoError(t, gerr, "create guardrail for %s", tc.name)
		t.Cleanup(func() { _ = srv.DeleteGuardrail(context.Background(), g.Id) })
		polReq.GuardrailIds = &[]string{g.Id}
	}
	pol, err := srv.CreatePolicy(ctx, polReq)
	require.NoError(t, err, "create policy for %s", tc.name)
	t.Cleanup(func() { _ = srv.DeletePolicy(context.Background(), pol.Id) })

	return sk.Key
}

// runLiveDiscoveryCase issues the discovery request and reports everything the
// vendor said before asserting on any of it. The log is the point on the first
// run: a live catalogue is the one input we do not control, so a failure has to
// arrive with the response that caused it rather than just a count.
func runLiveDiscoveryCase(t *testing.T, ctx context.Context, tc liveDiscoveryCase, cl *harness.Client, endpoint, proxyIP string) {
	t.Helper()

	// A single request is enough for the two non-listing outcomes, and retrying
	// them would burn the retry window waiting for a status that is never
	// coming.
	if tc.outcome != outcomeFiltered {
		code, body, err := cl.Get(ctx, endpoint, proxyIP, tc.path, tc.headers)
		require.NoError(t, err, "request must reach the proxy")
		t.Logf("[discovery] %s GET %s -> %d; body: %s", tc.name, tc.path, code, truncate(body, 2000))
		assert.NotEqual(t, 200, code,
			"%s serves no bounded listing, so a 200 here would mean the caller was handed a picker nothing narrows; body: %s",
			tc.name, truncate(body, 2000))

		// Which side refused is the whole distinction between these two
		// outcomes, and a NetBird error is the thing that tells them apart: the
		// middleware chain stamps its own name on anything it generates.
		if tc.outcome == outcomeDenied {
			assert.True(t, isProxyError(body),
				"%s serves no listing endpoint at all, so the proxy must refuse the request itself rather than forward it to an upstream that would answer for us; body: %s",
				tc.name, truncate(body, 2000))
			return
		}
		assert.False(t, isProxyError(body),
			"%s discovery must be routed to the configured upstream and refused by the vendor, not blocked by the proxy; body: %s",
			tc.name, truncate(body, 2000))
		return
	}

	code, body := callUntil(t, func() (int, string, error) {
		return cl.Get(ctx, endpoint, proxyIP, tc.path, tc.headers)
	}, 200)
	// Status only, not the body. A Bedrock listing embeds inference-profile
	// ARNs carrying the 12-digit AWS account id, and these job logs are
	// readable by anyone who can see the run. The ids line below is the finding
	// anyway. The failure paths below are the same log: a listing that fails to
	// arrive is an AWS refusal naming the resource it refused, and that name is
	// an ARN carrying the same account id.
	t.Logf("[discovery] %s GET %s -> %d", tc.name, tc.path, code)
	require.Equal(t, 200, code, "%s discovery must be served; response was %s", tc.name, bodyShape(body))

	ids, ok := listingIDs(body)
	require.Truef(t, ok,
		"%s answered discovery with something other than a {\"data\":[{\"id\":…}]} listing, which the filter forwards untouched — the caller would get an unbounded picker; response was %s",
		tc.name, bodyShape(body))
	sort.Strings(ids)
	t.Logf("[discovery] %s: %d ids after filtering: %s", tc.name, len(ids), strings.Join(ids, ", "))

	require.NotEmpty(t, ids, "%s filtered the listing down to nothing; the caller would see an empty picker", tc.name)

	permitted := make(map[string]struct{}, len(tc.permitted)*2)
	for _, id := range tc.permitted {
		permitted[id] = struct{}{}
		permitted[sharedllm.NormalizeAnthropicModel(id)] = struct{}{}
	}
	for _, id := range ids {
		_, direct := permitted[id]
		_, dated := permitted[sharedllm.NormalizeAnthropicModel(id)]
		// Bedrock ids carry a region prefix and version suffix the record may
		// not repeat; the proxy's filter tries the same forms.
		_, bedrock := permitted[sharedllm.NormalizeBedrockModel(id)]
		assert.Truef(t, direct || dated || bedrock,
			"%s offered %q, which no policy on this route permits — every entry the picker shows must be a request the guardrail would allow", tc.name, id)
	}
	for _, hidden := range tc.wantHidden {
		assert.NotContainsf(t, ids, hidden,
			"%s offered %q, which the provider enumerates but the policy does not permit", tc.name, hidden)
	}
}

// isProxyError reports whether a response body was generated by the middleware
// chain rather than forwarded from a vendor. Every chain-generated error names
// the middleware that raised it, which no upstream's error body does — so this
// separates "the proxy refused" from "the proxy routed it and the vendor
// refused", the two failures that otherwise look alike from the client side.
func isProxyError(body string) bool {
	return strings.Contains(body, `"middleware":`)
}

// listingIDs pulls the model ids out of a listing response. ok is false when
// the body is neither envelope the proxy's filter recognises — the two must
// stay in step, or this test reports "not a listing" for a response the proxy
// filtered perfectly well.
func listingIDs(body string) ([]string, bool) {
	var doc struct {
		// OpenAI's shape, which Anthropic adopted.
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
		// Bedrock returns inference-profile summaries under a key of its own,
		// with the id under a field of its own.
		Summaries []struct {
			ID string `json:"inferenceProfileId"`
		} `json:"inferenceProfileSummaries"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		return nil, false
	}
	switch {
	case doc.Data != nil:
		ids := make([]string, 0, len(doc.Data))
		for _, entry := range doc.Data {
			ids = append(ids, entry.ID)
		}
		return ids, true
	case doc.Summaries != nil:
		ids := make([]string, 0, len(doc.Summaries))
		for _, entry := range doc.Summaries {
			ids = append(ids, entry.ID)
		}
		return ids, true
	}
	return nil, false
}

func caseNames(cases []liveDiscoveryCase) []string {
	names := make([]string, 0, len(cases))
	for _, c := range cases {
		names = append(names, c.name)
	}
	return names
}

// bodyShape describes a response without quoting any of it: its size and the
// top-level keys it arrived under. That is what a discovery failure is
// diagnosed from — which envelope the vendor answered with — and it is all
// that may go in a message rendered into a public job log, because the values
// underneath can carry an ARN and its account id.
func bodyShape(body string) string {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		return strconv.Itoa(len(body)) + " bytes, not a JSON object"
	}
	keys := make([]string, 0, len(doc))
	for key := range doc {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return strconv.Itoa(len(body)) + " bytes, an empty JSON object"
	}
	return strconv.Itoa(len(body)) + " bytes, keyed by: " + strings.Join(keys, ", ")
}

// truncate bounds a logged response body. A live catalogue can run to tens of
// kilobytes, and the useful part is the front.
func truncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "… (" + strconv.Itoa(len(s)-limit) + " more bytes)"
}
