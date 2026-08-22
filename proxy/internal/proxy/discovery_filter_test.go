package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// jsonListingResponse builds a 200 model-listing response with the given
// body, as an upstream would return it.
func jsonListingResponse(body string) *http.Response {
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
	resp.Header.Set("Content-Type", "application/json")
	return resp
}

// listedIDs runs the filter and returns the ids left in the response.
func listedIDs(t *testing.T, allowed []string, body string) []string {
	t.Helper()
	resp := jsonListingResponse(body)                            //nolint:bodyclose // in-memory body, replaced by the filter
	require.NoError(t, modelDiscoveryFilter(allowed, nil)(resp)) //nolint:bodyclose // in-memory body, replaced by the filter

	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var doc struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(raw, &doc), "filtered body must stay valid JSON")

	ids := make([]string, 0, len(doc.Data))
	for _, entry := range doc.Data {
		ids = append(ids, entry.ID)
	}
	return ids
}

// TestModelDiscoveryFilter_KeepsOnlyAuthorisedModels covers the picker a
// developer sees: an unfiltered upstream list offers every model the shared
// key can reach, and each one the policy excludes is a request the chain
// denies a moment later.
func TestModelDiscoveryFilter_KeepsOnlyAuthorisedModels(t *testing.T) {
	ids := listedIDs(t, []string{"claude-sonnet-5", "claude-haiku-4-5"}, `{
		"data": [
			{"id": "claude-opus-5", "display_name": "Claude Opus 5"},
			{"id": "claude-sonnet-5", "display_name": "Claude Sonnet 5"},
			{"id": "claude-haiku-4-5"}
		],
		"has_more": false
	}`)

	assert.Equal(t, []string{"claude-sonnet-5", "claude-haiku-4-5"}, ids,
		"only the models the route authorises may reach the picker")
}

// TestModelDiscoveryFilter_MatchesDatedAndPrefixedIDs pins the two id forms
// a gateway returns for a model the operator registered plainly.
func TestModelDiscoveryFilter_MatchesDatedAndPrefixedIDs(t *testing.T) {
	ids := listedIDs(t, []string{"claude-sonnet-4-5", "anthropic.claude-opus-5"}, `{
		"data": [
			{"id": "claude-sonnet-4-5-20250929"},
			{"id": "bedrock/anthropic.claude-opus-5"},
			{"id": "gpt-4o"}
		]
	}`)

	assert.Equal(t, []string{"claude-sonnet-4-5-20250929", "bedrock/anthropic.claude-opus-5"}, ids,
		"a dated or provider-prefixed id must match its registered form")
}

// TestModelDiscoveryFilter_PreservesEnvelopeFields guards the rest of the
// document: clients read paging fields alongside data.
func TestModelDiscoveryFilter_PreservesEnvelopeFields(t *testing.T) {
	resp := jsonListingResponse(`{"data":[{"id":"claude-sonnet-5"}],"has_more":true,"first_id":"x"}`) //nolint:bodyclose // in-memory body, replaced by the filter
	require.NoError(t, modelDiscoveryFilter([]string{"claude-sonnet-5"}, nil)(resp))                  //nolint:bodyclose // in-memory body, replaced by the filter

	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var doc map[string]any
	require.NoError(t, json.Unmarshal(raw, &doc))
	assert.Equal(t, true, doc["has_more"], "paging fields must survive the rewrite")
	assert.Equal(t, "x", doc["first_id"])
	assert.Equal(t, strconv.Itoa(len(raw)), resp.Header.Get("Content-Length"),
		"Content-Length must match the rewritten body")
}

// TestModelDiscoveryFilter_PassesThroughUnfilterable covers the responses
// the filter must not touch: a compressed body it cannot parse, a non-JSON
// body, an error status, and a document with no data array.
func TestModelDiscoveryFilter_PassesThroughUnfilterable(t *testing.T) {
	cases := map[string]func() *http.Response{
		"compressed": func() *http.Response {
			resp := jsonListingResponse(`{"data":[{"id":"gpt-4o"}]}`)
			resp.Header.Set("Content-Encoding", "gzip")
			return resp
		},
		"not json": func() *http.Response {
			resp := jsonListingResponse(`{"data":[{"id":"gpt-4o"}]}`)
			resp.Header.Set("Content-Type", "text/html")
			return resp
		},
		"error status": func() *http.Response {
			resp := jsonListingResponse(`{"data":[{"id":"gpt-4o"}]}`)
			resp.StatusCode = http.StatusInternalServerError
			return resp
		},
		"no data array": func() *http.Response {
			return jsonListingResponse(`{"object":"list"}`)
		},
	}

	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			resp := build() //nolint:bodyclose // in-memory body, replaced by the filter
			original, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			resp.Body = io.NopCloser(bytes.NewReader(original))

			require.NoError(t, modelDiscoveryFilter([]string{"claude-sonnet-5"}, nil)(resp)) //nolint:bodyclose // in-memory body, replaced by the filter

			got, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Equal(t, string(original), string(got), "an unfilterable response must reach the client unchanged")
		})
	}
}

// TestModelDiscoveryFilter_RunsNextHook pins that an existing
// ModifyResponse hook still runs after filtering.
func TestModelDiscoveryFilter_RunsNextHook(t *testing.T) {
	called := false
	next := func(*http.Response) error {
		called = true
		return nil
	}

	resp := jsonListingResponse(`{"data":[{"id":"claude-sonnet-5"}]}`)                //nolint:bodyclose // in-memory body, replaced by the filter
	require.NoError(t, modelDiscoveryFilter([]string{"claude-sonnet-5"}, next)(resp)) //nolint:bodyclose // in-memory body, replaced by the filter
	assert.True(t, called, "the chained hook must still run")
}

// TestModelDiscoveryFilter_KeepsSlashBearingIDs covers self-hosted backends
// whose model ids carry a slash of their own. Treating the slash as a
// gateway prefix and keeping only the tail dropped every such model from
// the picker even though the policy named it exactly.
func TestModelDiscoveryFilter_KeepsSlashBearingIDs(t *testing.T) {
	ids := listedIDs(t, []string{"Qwen/Qwen2.5-0.5B-Instruct"}, `{
		"object": "list",
		"data": [
			{"id": "Qwen/Qwen2.5-0.5B-Instruct"},
			{"id": "Qwen/Qwen2.5-7B-Instruct"}
		]
	}`)

	assert.Equal(t, []string{"Qwen/Qwen2.5-0.5B-Instruct"}, ids,
		"a slash inside the model id is part of the id, not a provider prefix")
}

// TestModelDiscoveryFilter_ForwardsOversizedBodyIntact covers a listing past
// the buffering cap. The filter reads one byte beyond the cap to detect the
// size; forwarding only what it read would hand the client a body truncated
// at exactly 1 MiB — valid-looking, short, and unparseable as JSON. The bytes
// already read must be spliced back in front of the unread remainder so the
// response reaches the client exactly as the upstream sent it.
func TestModelDiscoveryFilter_ForwardsOversizedBodyIntact(t *testing.T) {
	// A well-formed listing whose single entry pads the body past the cap.
	padding := strings.Repeat("x", maxDiscoveryBodyBytes)
	body := `{"object":"list","data":[{"id":"gpt-4o","note":"` + padding + `"}]}`
	require.Greater(t, len(body), maxDiscoveryBodyBytes+1,
		"the fixture must exceed the cap by more than the one-byte probe")

	resp := jsonListingResponse(body)                        //nolint:bodyclose // in-memory body
	require.NoError(t, modelDiscoveryFilter(nil, nil)(resp)) //nolint:bodyclose // in-memory body

	got, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, len(body), len(got),
		"an oversized listing must reach the client whole, not truncated at the cap")
	assert.Equal(t, body, string(got), "the forwarded bytes must be the upstream's own")

	var doc map[string]json.RawMessage
	assert.NoError(t, json.Unmarshal(got, &doc),
		"the forwarded body must still parse as JSON")
}

// TestModelDiscoveryFilter_OversizedBodyKeepsUpstreamHeaders pins that the
// oversized path leaves the response metadata alone. Rewriting Content-Length
// to the truncated prefix is what made the corruption invisible to the client
// until it tried to parse.
func TestModelDiscoveryFilter_OversizedBodyKeepsUpstreamHeaders(t *testing.T) {
	padding := strings.Repeat("x", maxDiscoveryBodyBytes)
	body := `{"object":"list","data":[{"id":"gpt-4o","note":"` + padding + `"}]}`

	resp := jsonListingResponse(body) //nolint:bodyclose // in-memory body
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	require.NoError(t, modelDiscoveryFilter(nil, nil)(resp)) //nolint:bodyclose // in-memory body

	assert.Equal(t, int64(len(body)), resp.ContentLength,
		"ContentLength must keep describing the body the client receives")
	assert.Equal(t, strconv.Itoa(len(body)), resp.Header.Get("Content-Length"),
		"the Content-Length header must not be rewritten to the truncated prefix")
}
