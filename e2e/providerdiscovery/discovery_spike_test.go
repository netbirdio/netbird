//go:build e2e

// Package providerdiscovery is a credential-driven spike, not a regression
// suite. It calls each vendor's model-discovery endpoint DIRECTLY — no proxy,
// no tunnel, no containers — to answer a question the mock upstream cannot:
// what does each vendor return to a caller holding only the credential an
// operator gave us, and in what shape?
//
// That is the call management would have to make to populate the provider-config
// model picker from live data instead of the hand-maintained catalog in
// management/internals/modules/agentnetwork/catalog. Today that catalog is
// curated by hand — it carries comments tracking which models a vendor retired
// on which date — and it cannot know what a particular account may actually
// invoke.
//
// The load-bearing unknown is Bedrock. ListInferenceProfiles is a CONTROL PLANE
// operation on bedrock.<region>.amazonaws.com, while a provider record's
// upstream is bedrock-runtime.<region> because that is what InvokeModel needs.
// Whether a Bedrock API key (AWS_BEARER_TOKEN_BEDROCK) authorises the control
// plane at all is undocumented, and the answer decides whether live discovery
// for Bedrock is a small feature or needs SigV4 signing in management. The
// other three surfaces are here to corroborate the shape.
//
// NOTHING HERE ASSERTS A STATUS CODE, deliberately: the status is the finding.
// A probe fails the test only when its credential is present and the request
// could not be made at all, which is a harness problem rather than an answer.
package providerdiscovery

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2/google"

	"github.com/stretchr/testify/require"
)

// probeTimeout bounds a single vendor call. Generous for a discovery GET, and
// short enough that a hanging endpoint reports rather than stalls the job.
const probeTimeout = 20 * time.Second

// maxLoggedBody bounds what a probe echoes into the job log. A full model
// listing runs to tens of kilobytes and the useful part is the front; an error
// body is short and is reproduced whole.
const maxLoggedBody = 1500

// gcpScope matches the scope llm_router mints Vertex tokens under, so this
// probe exercises the same credential the proxy already uses in production
// rather than a differently-scoped one that might succeed where it fails.
const gcpScope = "https://www.googleapis.com/auth/cloud-platform"

// probe is one discovery endpoint to try.
type probe struct {
	// surface is the provider-config entry this informs (openai_api, …).
	surface string
	// variant distinguishes several candidate endpoints for one surface,
	// because part of the spike is finding out WHICH path answers.
	variant string
	url     string
	headers map[string]string
}

// result is what came back, including the failure cases — those are answers too.
type result struct {
	probe
	status int
	// shape names the JSON envelope the ids were found under, so the eventual
	// implementation knows which parser each surface needs.
	shape string
	ids   []string
	body  string
	err   error
}

// TestProviderModelDiscoverySpike probes every configured vendor and prints a
// verdict table. Read the log, not the pass/fail.
func TestProviderModelDiscoverySpike(t *testing.T) {
	probes := configuredProbes(t)
	if len(probes) == 0 {
		t.Skip("no provider credentials set; source ~/.llm-keys to run the discovery spike")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	results := make([]result, 0, len(probes))
	for _, p := range probes {
		t.Run(p.surface+"/"+p.variant, func(t *testing.T) {
			res := runProbe(ctx, p)
			results = append(results, res)

			// A transport error means we never got an answer — that is a broken
			// probe, not a finding about the vendor.
			require.NoError(t, res.err, "%s %s: request could not be made", p.surface, p.variant)

			t.Logf("[spike] %s %s -> %d", p.surface, p.variant, res.status)
			t.Logf("[spike] %s %s url: %s", p.surface, p.variant, p.url)
			if res.shape != "" {
				t.Logf("[spike] %s %s shape=%s ids=%d: %s",
					p.surface, p.variant, res.shape, len(res.ids), strings.Join(sample(res.ids, 12), ", "))
			}
			t.Logf("[spike] %s %s body: %s", p.surface, p.variant, truncate(res.body, maxLoggedBody))
		})
	}

	t.Log("[spike] ==================== VERDICT ====================")
	for _, r := range results {
		t.Logf("[spike] %-28s %-42s %3d  %s",
			r.surface+"/"+r.variant, verdict(r), r.status, shapeNote(r))
	}
	t.Log("[spike] =================================================")
}

// configuredProbes assembles the probe list from whichever credentials are
// present, mirroring the env-var gating the rest of the e2e suite uses.
func configuredProbes(t *testing.T) []probe {
	t.Helper()
	var ps []probe

	if k := os.Getenv("OPENAI_TOKEN"); k != "" {
		ps = append(ps, probe{
			surface: "openai_api", variant: "v1-models",
			url:     "https://api.openai.com/v1/models",
			headers: map[string]string{"Authorization": "Bearer " + k},
		})
	}

	if k := os.Getenv("ANTHROPIC_TOKEN"); k != "" {
		// limit=1000 because the default page is small and a picker wants the
		// whole catalogue in one call if it can get it.
		ps = append(ps, probe{
			surface: "anthropic_api", variant: "v1-models",
			url: "https://api.anthropic.com/v1/models?limit=1000",
			headers: map[string]string{
				"x-api-key":         k,
				"anthropic-version": "2023-06-01",
			},
		})
	}

	ps = append(ps, bedrockProbes()...)
	ps = append(ps, vertexProbes(t)...)
	return ps
}

// bedrockProbes covers the three candidate hosts/paths. The runtime probe is
// the control: we already know it 404s, and having it in the same table makes
// the control-plane result unambiguous rather than a lone data point.
func bedrockProbes() []probe {
	k := os.Getenv("AWS_BEARER_TOKEN_BEDROCK")
	if k == "" {
		return nil
	}
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "eu-central-1"
	}
	auth := map[string]string{"Authorization": "Bearer " + k}
	return []probe{
		{
			surface: "bedrock_api", variant: "control-inference-profiles",
			url:     "https://bedrock." + region + ".amazonaws.com/inference-profiles",
			headers: auth,
		},
		{
			surface: "bedrock_api", variant: "control-foundation-models",
			url:     "https://bedrock." + region + ".amazonaws.com/foundation-models",
			headers: auth,
		},
		{
			// The control: the record's real upstream, which we expect to
			// answer <UnknownOperationException/>.
			surface: "bedrock_api", variant: "runtime-inference-profiles",
			url:     "https://bedrock-runtime." + region + ".amazonaws.com/inference-profiles",
			headers: auth,
		},
	}
}

// vertexProbes covers the publisher-model listing under both API versions and
// both the global and project-scoped forms, because which one answers is itself
// part of what the spike is for.
func vertexProbes(t *testing.T) []probe {
	t.Helper()
	sa := os.Getenv("GOOGLE_VERTEX_SA_BASE64")
	project := os.Getenv("GOOGLE_VERTEX_PROJECT")
	if sa == "" || project == "" {
		return nil
	}
	region := os.Getenv("GOOGLE_VERTEX_REGION")
	if region == "" {
		region = "global"
	}
	host := "aiplatform.googleapis.com"
	if region != "global" {
		host = region + "-aiplatform.googleapis.com"
	}

	token, err := mintGCPToken(sa)
	if err != nil {
		// Report rather than fail: a credential we cannot mint from is a
		// finding about the credential, and the other surfaces still have
		// something to say.
		t.Logf("[spike] vertex_ai_api: could not mint an OAuth token from the service-account key: %v", err)
		return nil
	}
	auth := map[string]string{"Authorization": "Bearer " + token}

	return []probe{
		{
			surface: "vertex_ai_api", variant: "v1-publishers",
			url:     "https://" + host + "/v1/publishers/anthropic/models",
			headers: auth,
		},
		{
			surface: "vertex_ai_api", variant: "v1beta1-publishers",
			url:     "https://" + host + "/v1beta1/publishers/anthropic/models",
			headers: auth,
		},
		{
			surface: "vertex_ai_api", variant: "v1-project-scoped",
			url: "https://" + host + "/v1/projects/" + project +
				"/locations/" + region + "/publishers/anthropic/models",
			headers: auth,
		},
		{
			// The project-scoped list under the version that actually answers.
			// The first run's publisher list returned only two models, fewer
			// than the catalog ships, which is what a publisher-global list
			// looks like rather than what THIS project has enabled — and
			// per-project availability is most of why live discovery beats a
			// static catalogue. The v1 form 404s, so v1beta1 is the one form
			// left that could carry it.
			surface: "vertex_ai_api", variant: "v1beta1-project-scoped",
			url: "https://" + host + "/v1beta1/projects/" + project +
				"/locations/" + region + "/publishers/anthropic/models",
			headers: auth,
		},
		{
			// A publisher model is addressed as "<id>@<version>" on the
			// rawPredict path, and the plain listing reports one versionId per
			// model. If a model has several live versions, a picker that only
			// ever saw one would silently hide the rest.
			surface: "vertex_ai_api", variant: "v1beta1-all-versions",
			url:     "https://" + host + "/v1beta1/publishers/anthropic/models?listAllVersions=true",
			headers: auth,
		},
	}
}

// mintGCPToken builds an access token from the base64 service-account key,
// the same way llm_router does at request time.
func mintGCPToken(saKeyB64 string) (string, error) {
	jsonKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(saKeyB64))
	if err != nil {
		return "", fmt.Errorf("decode service-account key: %w", err)
	}
	conf, err := google.JWTConfigFromJSON(jsonKey, gcpScope)
	if err != nil {
		return "", fmt.Errorf("parse service-account key: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	tok, err := conf.TokenSource(ctx).Token()
	if err != nil {
		return "", fmt.Errorf("mint token: %w", err)
	}
	return tok.AccessToken, nil
}

// runProbe issues one request and extracts whatever model ids it can find.
func runProbe(ctx context.Context, p probe) result {
	res := result{probe: p}

	reqCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, p.url, nil)
	if err != nil {
		res.err = err
		return res
	}
	for k, v := range p.headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		res.err = err
		return res
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		res.err = err
		return res
	}
	res.status = resp.StatusCode
	res.body = string(body)
	res.shape, res.ids = extractIDs(body)
	return res
}

// listingShapes maps a response envelope to the field naming the model id
// inside it. Each vendor invented its own; a picker has to read all of them.
var listingShapes = []struct {
	envelope string
	idField  string
}{
	{"data", "id"}, // OpenAI, Anthropic
	{"inferenceProfileSummaries", "inferenceProfileId"}, // Bedrock control plane
	{"modelSummaries", "modelId"},                       // Bedrock foundation models
	{"publisherModels", "name"},                         // Vertex publisher models
	{"models", "name"},                                  // Vertex, older shape
}

// extractIDs returns the envelope that matched and the ids under it. An empty
// shape means the body is not a listing this spike recognises — which for an
// error response is the expected outcome.
func extractIDs(body []byte) (string, []string) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", nil
	}
	for _, shape := range listingShapes {
		raw, ok := doc[shape.envelope]
		if !ok {
			continue
		}
		var entries []map[string]json.RawMessage
		if err := json.Unmarshal(raw, &entries); err != nil {
			continue
		}
		ids := make([]string, 0, len(entries))
		for _, entry := range entries {
			var id string
			if err := json.Unmarshal(entry[shape.idField], &id); err != nil || id == "" {
				continue
			}
			// Vertex splits the wire id across two fields: a publisher model is
			// addressed as "<id>@<version>" on rawPredict, so a listing that
			// reported only the name would look usable and not be.
			var version string
			if raw, ok := entry["versionId"]; ok {
				if err := json.Unmarshal(raw, &version); err == nil && version != "" {
					id += "@" + version
				}
			}
			ids = append(ids, id)
		}
		return shape.envelope, ids
	}
	return "", nil
}

// verdict renders the one-line answer for the summary table.
func verdict(r result) string {
	switch {
	case r.err != nil:
		return "REQUEST FAILED"
	case r.status == http.StatusOK && len(r.ids) > 0:
		return "USABLE — listing returned"
	case r.status == http.StatusOK:
		return "200 but no ids parsed"
	case r.status == http.StatusUnauthorized, r.status == http.StatusForbidden:
		return "CREDENTIAL REJECTED"
	case r.status == http.StatusNotFound:
		return "NOT SERVED HERE"
	default:
		return "UNEXPECTED"
	}
}

func shapeNote(r result) string {
	if r.shape == "" {
		return ""
	}
	return fmt.Sprintf("shape=%s ids=%d", r.shape, len(r.ids))
}

func sample(ids []string, n int) []string {
	if len(ids) <= n {
		return ids
	}
	return append(append([]string{}, ids[:n]...), fmt.Sprintf("… +%d more", len(ids)-n))
}

func truncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[:limit] + fmt.Sprintf("… (%d more bytes)", len(s)-limit)
}
