//go:build e2e

package agentnetwork

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/catalog"
	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/modeldiscovery"
	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/pricing"
	sharedllm "github.com/netbirdio/netbird/shared/llm"
)

// TestDebugBedrockProfileCount investigates a listing that reports 100+ models
// for an account whose console shows 38 in the same region. It asserts almost
// nothing — it prints what the production path throws away.
//
// parseListing keeps an id, a name and a status and discards the rest of every
// summary, so the type, the geography and whether a nextToken came back never
// reach a log line. Fetch then works from a list that has already been
// filtered. Neither can answer where the surplus comes from.
//
// It reads the listing three ways:
//
//	[1] one GET with no query parameters — byte for byte what Fetch issues,
//	    which shows how much of the account a single page carries
//	[2] the same call followed through nextToken, for the real total
//	[3] Fetch itself, for what reaches the dashboard
//
// then decomposes the full set by status, type, geography and vendor, and
// counts distinct models after normalization. Two outcomes need opposite
// fixes and look identical in the dashboard:
//
//   - distinct-after-normalization lands near the console's count → the
//     surplus is one model offered once per geography, and the question is
//     what to offer rather than what broke
//   - it does not → we are being handed profiles the console does not show,
//     and the filter is what to look at
//
// Uses the same credential as the rest of the live suite:
//
//	go test -tags e2e ./e2e/agentnetwork/ -run TestDebugBedrockProfileCount -v
func TestDebugBedrockProfileCount(t *testing.T) {
	token := os.Getenv("AWS_BEARER_TOKEN_BEDROCK")
	if token == "" {
		t.Skip("AWS_BEARER_TOKEN_BEDROCK not set; source ~/.llm-keys to run the Bedrock count debug")
	}
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "eu-central-1"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	host := "bedrock." + region + ".amazonaws.com"
	t.Logf("=== region %s, control plane %s ===", region, host)

	// [1] Exactly what Fetch asks for: no maxResults, no type filter.
	first, firstRaw := listInferenceProfiles(t, ctx, host, token, nil)
	t.Logf("[1] production-shaped call: %d summaries, %d bytes, nextToken present: %t",
		len(first.Summaries), len(firstRaw), first.NextToken != "")

	// [2] Followed to exhaustion, so the total is not just a page size.
	all := append([]bedrockProfileSummary(nil), first.Summaries...)
	next, pages := first.NextToken, 1
	for next != "" && pages < 20 {
		page, _ := listInferenceProfiles(t, ctx, host, token, map[string]string{"nextToken": next})
		all = append(all, page.Summaries...)
		next, pages = page.NextToken, pages+1
	}
	t.Logf("[2] paginated: %d summaries across %d page(s)", len(all), pages)
	if next != "" {
		t.Logf("    WARNING: stopped at the page cap with a nextToken still outstanding")
	}

	// [3] The path the Load models button drives, with its ACTIVE filter and
	// its dedup.
	var cl modeldiscovery.Client
	fetched, err := cl.Fetch(ctx, modeldiscovery.Request{
		CatalogID:   "bedrock_api",
		UpstreamURL: "https://bedrock-runtime." + region + ".amazonaws.com",
		APIKey:      token,
	})
	require.NoError(t, err, "Fetch must reach the control plane")
	t.Logf("[3] Fetch returned %d models (this is what the dashboard renders)", len(fetched))
	if len(first.Summaries) == len(all) && len(fetched) > len(all) {
		t.Logf("    NOTE: Fetch returned more than the raw listing — the surplus is ours, not AWS's")
	}

	byStatus, byType, byGeo, byVendor := map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}
	normalized := map[string]struct{}{}
	perModel := map[string][]string{}
	active := 0

	for _, s := range all {
		byStatus[orAbsent(s.Status)]++
		byType[orAbsent(s.Type)]++
		geo, vendor := splitBedrockProfileID(s.ID)
		byGeo[geo]++
		byVendor[vendor]++

		if s.Status != "" && !strings.EqualFold(s.Status, "ACTIVE") {
			continue
		}
		active++
		key := sharedllm.NormalizeBedrockModel(s.ID)
		normalized[key] = struct{}{}
		perModel[key] = append(perModel[key], s.ID)
	}

	t.Logf("--- ACTIVE summaries: %d of %d", active, len(all))
	t.Logf("--- distinct models after normalization: %d  <<< compare with the console", len(normalized))
	logProfileCounts(t, "by status", byStatus)
	logProfileCounts(t, "by type", byType)
	logProfileCounts(t, "by geography", byGeo)
	logProfileCounts(t, "by vendor", byVendor)

	var repeated []string
	for key, ids := range perModel {
		if len(ids) > 1 {
			sort.Strings(ids)
			repeated = append(repeated, key+" ("+strings.Join(ids, ", ")+")")
		}
	}
	sort.Strings(repeated)
	t.Logf("--- models offered under more than one geography: %d", len(repeated))
	for _, line := range repeated {
		t.Logf("      %s", line)
	}

	// A model the catalog cannot price is a catalog gap, not a normalization
	// failure. Both render as $0 with a yellow border and need opposite fixes.
	entry, ok := catalog.Lookup("bedrock_api")
	require.True(t, ok)
	var priced, unpriced []string
	for id := range normalized {
		if _, known := pricing.LookupDefault(entry.PricingSurfaces, id); known {
			priced = append(priced, id)
			continue
		}
		unpriced = append(unpriced, id)
	}
	sort.Strings(priced)
	sort.Strings(unpriced)
	t.Logf("--- priced by the catalog: %d", len(priced))
	for _, id := range priced {
		t.Logf("      + %s", id)
	}
	t.Logf("--- NOT priced by the catalog: %d  (catalog coverage, not normalization)", len(unpriced))
	for _, id := range unpriced {
		t.Logf("      - %s", id)
	}
}

type bedrockProfileSummary struct {
	ID     string `json:"inferenceProfileId"`
	Name   string `json:"inferenceProfileName"`
	Status string `json:"status"`
	Type   string `json:"type"`
	ARN    string `json:"inferenceProfileArn"`
}

type bedrockProfilePage struct {
	Summaries []bedrockProfileSummary `json:"inferenceProfileSummaries"`
	NextToken string                  `json:"nextToken"`
}

// listInferenceProfiles calls the control plane directly so the whole summary
// is visible, rather than the three fields parseListing keeps.
func listInferenceProfiles(t *testing.T, ctx context.Context, host, token string, query map[string]string) (bedrockProfilePage, []byte) {
	t.Helper()

	target := url.URL{Scheme: "https", Host: host, Path: "/inference-profiles"}
	if len(query) > 0 {
		q := target.Query()
		for k, v := range query {
			q.Set(k, v)
		}
		target.RawQuery = q.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err, "reach the Bedrock control plane")
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	require.NoError(t, err)
	if resp.StatusCode != http.StatusOK {
		// The body is the point of a failure here: an IAM denial names the
		// action it refused, which is a different fix from a bad token.
		t.Logf("control plane answered %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
		t.Logf("  x-amzn-errortype: %s", resp.Header.Get("x-amzn-errortype"))
	}
	require.Equal(t, http.StatusOK, resp.StatusCode, "control plane must answer the listing")

	var page bedrockProfilePage
	require.NoError(t, json.Unmarshal(raw, &page), "listing must parse")
	return page, raw
}

// splitBedrockProfileID reports the geography and vendor segments of a
// profile id.
func splitBedrockProfileID(id string) (geo, vendor string) {
	parts := strings.SplitN(id, ".", 3)
	switch len(parts) {
	case 3:
		return parts[0], parts[1]
	case 2:
		return "(none)", parts[0]
	default:
		return "(none)", "(none)"
	}
}

func orAbsent(s string) string {
	if s == "" {
		return "(absent)"
	}
	return s
}

func logProfileCounts(t *testing.T, label string, counts map[string]int) {
	t.Helper()
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if counts[keys[i]] != counts[keys[j]] {
			return counts[keys[i]] > counts[keys[j]]
		}
		return keys[i] < keys[j]
	})
	t.Logf("--- %s:", label)
	for _, k := range keys {
		t.Logf("      %-30s %d", k, counts[k])
	}
}
