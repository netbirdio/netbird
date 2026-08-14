package llm_identity_inject

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/proxy/internal/middleware"
)

const (
	litellmProvider = "ainp_litellm-test"
	portkeyProvider = "ainp_portkey-test"
)

func newInput(resolvedProvider, userID string, groups []string) *middleware.Input {
	return &middleware.Input{
		Slot:       middleware.SlotOnRequest,
		AccountID:  "acct-test",
		UserID:     userID,
		UserGroups: groups,
		SourceIP:   "100.64.0.5",
		RequestID:  "req-1",
		Metadata: []middleware.KV{
			{Key: middleware.KeyLLMResolvedProviderID, Value: resolvedProvider},
		},
	}
}

func liteLLMRule() ProviderInjection {
	return ProviderInjection{
		ProviderID: litellmProvider,
		HeaderPair: &HeaderPairRule{
			EndUserIDHeader: "x-litellm-end-user-id",
			TagsHeader:      "x-litellm-tags",
		},
	}
}

func TestMiddlewareIdentity(t *testing.T) {
	mw := New(Config{})
	assert.Equal(t, ID, mw.ID())
	assert.Equal(t, Version, mw.Version())
	assert.Equal(t, middleware.SlotOnRequest, mw.Slot())
	assert.True(t, mw.MutationsSupported())
	assert.Empty(t, mw.MetadataKeys(), "middleware emits no metadata")
	assert.Nil(t, mw.AcceptedContentTypes())
	require.NoError(t, mw.Close())
}

func TestInject_MatchedProvider_StampsHeaders(t *testing.T) {
	mw := New(Config{Providers: []ProviderInjection{liteLLMRule()}})
	in := newInput(litellmProvider, "alice", []string{"grp-eng", "grp-it"})

	out, err := mw.Invoke(context.Background(), in)
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.Equal(t, middleware.DecisionAllow, out.Decision)
	require.NotNil(t, out.Mutations)

	// Strips the same headers we're about to add (anti-spoof).
	assert.ElementsMatch(t,
		[]string{"x-litellm-end-user-id", "x-litellm-tags"},
		out.Mutations.HeadersRemove,
		"every injected header must also appear in HeadersRemove so client-supplied values are wiped before our trusted values land")

	added := map[string]string{}
	for _, kv := range out.Mutations.HeadersAdd {
		added[kv.Key] = kv.Value
	}
	assert.Equal(t, "alice", added["x-litellm-end-user-id"])
	assert.Equal(t, "grp-eng,grp-it", added["x-litellm-tags"], "tags CSV must be sorted")
}

func TestInject_UnmatchedProvider_NoMutations(t *testing.T) {
	mw := New(Config{Providers: []ProviderInjection{liteLLMRule()}})
	in := newInput("ainp_some-other-provider", "alice", []string{"grp-eng"})

	out, err := mw.Invoke(context.Background(), in)
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.Equal(t, middleware.DecisionAllow, out.Decision)
	assert.Nil(t, out.Mutations, "non-LiteLLM resolved provider must produce no mutations")
}

func TestInject_NoResolvedProvider_NoMutations(t *testing.T) {
	mw := New(Config{Providers: []ProviderInjection{liteLLMRule()}})
	in := &middleware.Input{Slot: middleware.SlotOnRequest, UserID: "alice"}

	out, err := mw.Invoke(context.Background(), in)
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.Nil(t, out.Mutations,
		"missing llm.resolved_provider_id metadata means the router didn't run; never stamp identity blindly")
}

func TestInject_PartialRule_StampsOnlyConfiguredHeaders(t *testing.T) {
	mw := New(Config{Providers: []ProviderInjection{{
		ProviderID: litellmProvider,
		HeaderPair: &HeaderPairRule{
			EndUserIDHeader: "x-litellm-end-user-id",
			// TagsHeader intentionally empty.
		},
	}}})
	in := newInput(litellmProvider, "alice", []string{"grp-eng"})

	out, err := mw.Invoke(context.Background(), in)
	require.NoError(t, err)
	require.NotNil(t, out)
	require.NotNil(t, out.Mutations)

	assert.Equal(t, []string{"x-litellm-end-user-id"}, out.Mutations.HeadersRemove,
		"only configured header should be stripped")
	require.Len(t, out.Mutations.HeadersAdd, 1)
	assert.Equal(t, "x-litellm-end-user-id", out.Mutations.HeadersAdd[0].Key)
	assert.Equal(t, "alice", out.Mutations.HeadersAdd[0].Value)
}

func TestInject_EmptyIdentity_StripsButDoesNotAdd(t *testing.T) {
	// Caller has no UserID and no groups. We still strip the headers
	// (so the client can't inject identity) but we don't add empty
	// values that would mislead the gateway.
	mw := New(Config{Providers: []ProviderInjection{liteLLMRule()}})
	in := newInput(litellmProvider, "", nil)
	in.AccountID = ""
	in.SourceIP = ""
	in.RequestID = ""

	out, err := mw.Invoke(context.Background(), in)
	require.NoError(t, err)
	require.NotNil(t, out)
	require.NotNil(t, out.Mutations)

	assert.ElementsMatch(t,
		[]string{"x-litellm-end-user-id", "x-litellm-tags"},
		out.Mutations.HeadersRemove,
		"identity headers must be stripped even when we don't have values to add — anti-spoof")
	assert.Empty(t, out.Mutations.HeadersAdd,
		"no NetBird identity available; do not stamp empty / misleading values")
}

func TestInject_TagsCSV_DedupesAndSorts(t *testing.T) {
	mw := New(Config{Providers: []ProviderInjection{liteLLMRule()}})
	in := newInput(litellmProvider, "alice", []string{"grp-zzz", "grp-aaa", "grp-zzz", "", " "})

	out, err := mw.Invoke(context.Background(), in)
	require.NoError(t, err)
	require.NotNil(t, out)
	require.NotNil(t, out.Mutations)

	for _, kv := range out.Mutations.HeadersAdd {
		if kv.Key == "x-litellm-tags" {
			assert.Equal(t, "grp-aaa,grp-zzz", kv.Value,
				"tags CSV must dedupe, drop empty, and sort")
			return
		}
	}
	t.Fatalf("expected x-litellm-tags in HeadersAdd; got %v", out.Mutations.HeadersAdd)
}

func TestFactory_RejectsBadJSON(t *testing.T) {
	_, err := Factory{}.New([]byte("{not json"))
	require.Error(t, err)
}

func TestFactory_AcceptsEmptyShapes(t *testing.T) {
	for _, raw := range [][]byte{nil, []byte(""), []byte(" "), []byte("null"), []byte("{}"), []byte("[]")} {
		mw, err := Factory{}.New(raw)
		require.NoError(t, err)
		require.NotNil(t, mw)

		out, ierr := mw.Invoke(context.Background(),
			newInput(litellmProvider, "alice", []string{"grp-eng"}))
		require.NoError(t, ierr)
		assert.Equal(t, middleware.DecisionAllow, out.Decision)
		assert.Nil(t, out.Mutations,
			"empty config means no providers to inject for; every resolved provider passes through")
	}
}

func TestFactory_DropsInjectionRuleWithEmptyHeaders(t *testing.T) {
	mw, err := Factory{}.New([]byte(`{"providers":[{"provider_id":"x"}]}`))
	require.NoError(t, err)
	out, ierr := mw.Invoke(context.Background(), newInput("x", "alice", []string{"grp-eng"}))
	require.NoError(t, ierr)
	assert.Nil(t, out.Mutations,
		"a rule with no header names is functionally a no-op and must be dropped at New() time")
}

// TestInject_TagsFromAuthorisingMetadata pins that when llm_router has
// emitted llm.authorising_groups, the inject middleware uses THAT
// (the per-request authorising intersection) for the tags header — not
// the full UserGroups, which can include groups unrelated to this
// request's routing.
func TestInject_TagsFromAuthorisingMetadata(t *testing.T) {
	mw := New(Config{Providers: []ProviderInjection{liteLLMRule()}})
	in := newInput(litellmProvider, "alice", []string{"grp-eng", "grp-it", "grp-oncall"})
	in.Metadata = append(in.Metadata, middleware.KV{
		Key:   middleware.KeyLLMAuthorisingGroups,
		Value: "grp-eng",
	})

	out, err := mw.Invoke(context.Background(), in)
	require.NoError(t, err)
	require.NotNil(t, out)
	require.NotNil(t, out.Mutations)

	for _, kv := range out.Mutations.HeadersAdd {
		if kv.Key == "x-litellm-tags" {
			assert.Equal(t, "grp-eng", kv.Value,
				"tags must come from llm.authorising_groups, not the full UserGroups; unrelated peer groups must not leak")
			return
		}
	}
	t.Fatalf("expected x-litellm-tags in HeadersAdd; got %v", out.Mutations.HeadersAdd)
}

// TestInject_TagsFallsBackToUserGroups pins the defensive fallback: if
// llm_router didn't emit authorising-groups metadata (chain
// misconfiguration) the middleware uses UserGroups so identity is
// still stamped, just over-broad.
func TestInject_TagsFallsBackToUserGroups(t *testing.T) {
	mw := New(Config{Providers: []ProviderInjection{liteLLMRule()}})
	in := newInput(litellmProvider, "alice", []string{"grp-eng", "grp-it"})
	// No llm.authorising_groups metadata.

	out, err := mw.Invoke(context.Background(), in)
	require.NoError(t, err)
	require.NotNil(t, out)
	require.NotNil(t, out.Mutations)

	for _, kv := range out.Mutations.HeadersAdd {
		if kv.Key == "x-litellm-tags" {
			assert.Equal(t, "grp-eng,grp-it", kv.Value,
				"absent metadata must fall back to the full UserGroups CSV")
			return
		}
	}
	t.Fatalf("expected x-litellm-tags in HeadersAdd; got %v", out.Mutations.HeadersAdd)
}

// portkeyRule is the JSONMetadata-shape analogue of liteLLMRule: a
// single x-portkey-metadata header carrying _user and groups, with
// Portkey's 128-byte per-value cap.
func portkeyRule() ProviderInjection {
	return ProviderInjection{
		ProviderID: portkeyProvider,
		JSONMetadata: &JSONMetadataRule{
			Header:         "x-portkey-metadata",
			UserKey:        "_user",
			GroupsKey:      "groups",
			MaxValueLength: 128,
		},
	}
}

// TestInject_JSONMetadata_StampsHeader pins the Portkey-style emission:
// one header carrying a JSON envelope with reserved keys for user
// identity and groups CSV.
func TestInject_JSONMetadata_StampsHeader(t *testing.T) {
	mw := New(Config{Providers: []ProviderInjection{portkeyRule()}})
	in := newInput(portkeyProvider, "alice", []string{"grp-eng", "grp-it"})
	in.UserEmail = "alice@example.com"

	out, err := mw.Invoke(context.Background(), in)
	require.NoError(t, err)
	require.NotNil(t, out)
	require.NotNil(t, out.Mutations)

	assert.Equal(t, []string{"x-portkey-metadata"}, out.Mutations.HeadersRemove,
		"the JSON header must be stripped before we add our trusted value")
	require.Len(t, out.Mutations.HeadersAdd, 1)
	added := out.Mutations.HeadersAdd[0]
	assert.Equal(t, "x-portkey-metadata", added.Key)

	var payload map[string]string
	require.NoError(t, json.Unmarshal([]byte(added.Value), &payload))
	assert.Equal(t, "alice@example.com", payload["_user"],
		"_user reserved key carries the display identity (UserEmail)")
	assert.Equal(t, "grp-eng,grp-it", payload["groups"],
		"groups key carries the sorted CSV of group display names")
}

// TestInject_JSONMetadata_TruncatesValues pins the per-value byte cap.
// Portkey rejects metadata values longer than 128 chars; oversized
// values are truncated rather than failing the request.
func TestInject_JSONMetadata_TruncatesValues(t *testing.T) {
	mw := New(Config{Providers: []ProviderInjection{portkeyRule()}})
	in := newInput(portkeyProvider, "alice", []string{"grp-eng"})
	in.UserEmail = strings.Repeat("a", 200) + "@example.com"

	out, err := mw.Invoke(context.Background(), in)
	require.NoError(t, err)
	require.NotNil(t, out.Mutations)
	require.Len(t, out.Mutations.HeadersAdd, 1)

	var payload map[string]string
	require.NoError(t, json.Unmarshal([]byte(out.Mutations.HeadersAdd[0].Value), &payload))
	assert.Len(t, payload["_user"], 128,
		"per-value byte length must be capped at MaxValueLength")
}

// TestInject_JSONMetadata_Sanitize pins the AWS-Bedrock sanitization path: when
// Sanitize is set, characters outside Bedrock's accepted metadata class
// (notably the groups CSV comma and arbitrary characters in group display
// names) are replaced with '_' so Bedrock doesn't reject the request. Allowed
// characters (letters, digits, spaces, and @ . _ : / + - =) pass through.
func TestInject_JSONMetadata_Sanitize(t *testing.T) {
	rule := ProviderInjection{
		ProviderID: portkeyProvider,
		JSONMetadata: &JSONMetadataRule{
			Header:         "X-Amzn-Bedrock-Request-Metadata",
			UserKey:        "user",
			GroupsKey:      "group",
			MaxValueLength: 256,
			Sanitize:       true,
		},
	}
	mw := New(Config{Providers: []ProviderInjection{rule}})
	in := newInput(portkeyProvider, "alice", []string{"g1", "g2"})
	in.UserEmail = "alice@example.com"
	// Group display names carry characters Bedrock rejects (comma, '#'); the CSV
	// join adds another comma between the two groups.
	in.UserGroupNames = []string{"Eng,Team", "Ops#1"}

	out, err := mw.Invoke(context.Background(), in)
	require.NoError(t, err)
	require.NotNil(t, out.Mutations)
	require.Len(t, out.Mutations.HeadersAdd, 1)
	added := out.Mutations.HeadersAdd[0]
	assert.Equal(t, "X-Amzn-Bedrock-Request-Metadata", added.Key,
		"the Bedrock cost-allocation header carries the metadata JSON")

	var payload map[string]string
	require.NoError(t, json.Unmarshal([]byte(added.Value), &payload))
	assert.Equal(t, "alice@example.com", payload["user"],
		"'@' and '.' are in Bedrock's accepted set and must be preserved")
	assert.NotContains(t, payload["group"], ",", "commas must be sanitized — Bedrock rejects them")
	assert.NotContains(t, payload["group"], "#", "disallowed characters must be sanitized")
	assert.Contains(t, payload["group"], "Eng", "allowed characters must be preserved")
}

// TestInject_JSONMetadata_EmptyIdentity_StripsButDoesNotAdd verifies the
// anti-spoof Remove still fires when there's nothing to stamp.
func TestInject_JSONMetadata_EmptyIdentity_StripsButDoesNotAdd(t *testing.T) {
	mw := New(Config{Providers: []ProviderInjection{portkeyRule()}})
	in := newInput(portkeyProvider, "", nil)
	in.UserEmail = ""

	out, err := mw.Invoke(context.Background(), in)
	require.NoError(t, err)
	require.NotNil(t, out.Mutations)

	assert.Equal(t, []string{"x-portkey-metadata"}, out.Mutations.HeadersRemove,
		"strip even with no payload — client can't smuggle identity headers")
	assert.Empty(t, out.Mutations.HeadersAdd,
		"no NetBird identity available; do not stamp empty / misleading values")
}

// TestFactory_RejectsRuleWithBothShapes pins the configuration-error
// guard: a rule that sets both HeaderPair and JSONMetadata is dropped
// at New() time rather than guessing which wins.
func TestFactory_RejectsRuleWithBothShapes(t *testing.T) {
	mw := New(Config{Providers: []ProviderInjection{{
		ProviderID: litellmProvider,
		HeaderPair: &HeaderPairRule{
			EndUserIDHeader: "x-litellm-end-user-id",
		},
		JSONMetadata: &JSONMetadataRule{
			Header:  "x-portkey-metadata",
			UserKey: "_user",
		},
	}}})
	in := newInput(litellmProvider, "alice", []string{"grp-eng"})

	out, err := mw.Invoke(context.Background(), in)
	require.NoError(t, err)
	assert.Nil(t, out.Mutations,
		"a rule that sets both shapes is ambiguous and must be dropped at New() time")
}

// liteLLMRuleWithBody is the LiteLLM-style rule with body tag injection
// enabled (matches the catalog default).
func liteLLMRuleWithBody() ProviderInjection {
	return ProviderInjection{
		ProviderID: litellmProvider,
		HeaderPair: &HeaderPairRule{
			EndUserIDHeader: "x-litellm-end-user-id",
			TagsHeader:      "x-litellm-tags",
			TagsInBody:      true,
		},
	}
}

// TestInject_BodyTags_AddsMetadataTags pins the body-inject path that
// LiteLLM's _tag_max_budget_check requires. With TagsInBody set, the
// middleware writes the authorising-groups slice into
// request.metadata.tags (in addition to the header).
func TestInject_BodyTags_AddsMetadataTags(t *testing.T) {
	mw := New(Config{Providers: []ProviderInjection{liteLLMRuleWithBody()}})
	in := newInput(litellmProvider, "alice", []string{"grp-eng", "grp-sre"})
	in.Body = []byte(`{"model":"gpt-4o-mini","messages":[]}`)

	out, err := mw.Invoke(context.Background(), in)
	require.NoError(t, err)
	require.NotNil(t, out.Mutations)
	require.NotEmpty(t, out.Mutations.BodyReplace, "body must be rewritten when TagsInBody is set")

	var doc map[string]any
	require.NoError(t, json.Unmarshal(out.Mutations.BodyReplace, &doc))
	meta, ok := doc["metadata"].(map[string]any)
	require.True(t, ok, "metadata must be an object")
	tags, ok := meta["tags"].([]any)
	require.True(t, ok, "metadata.tags must be a JSON array")
	got := make([]string, 0, len(tags))
	for _, t := range tags {
		s, _ := t.(string)
		got = append(got, s)
	}
	assert.Equal(t, []string{"grp-eng", "grp-sre"}, got,
		"metadata.tags must carry the sorted authorising-groups slice")
	assert.Equal(t, "gpt-4o-mini", doc["model"],
		"the rest of the body must be preserved verbatim")
}

// TestInject_BodyTags_PreservesExistingMetadata pins that an existing
// metadata object on the request is merged with our tags rather than
// clobbered — clients sometimes set metadata fields the proxy
// shouldn't blow away (jobID, taskName, etc.).
func TestInject_BodyTags_PreservesExistingMetadata(t *testing.T) {
	mw := New(Config{Providers: []ProviderInjection{liteLLMRuleWithBody()}})
	in := newInput(litellmProvider, "alice", []string{"grp-eng"})
	in.Body = []byte(`{"model":"gpt-4o-mini","metadata":{"jobID":"j-42","tags":["should-be-replaced"]}}`)

	out, err := mw.Invoke(context.Background(), in)
	require.NoError(t, err)
	require.NotEmpty(t, out.Mutations.BodyReplace)

	var doc map[string]any
	require.NoError(t, json.Unmarshal(out.Mutations.BodyReplace, &doc))
	meta := doc["metadata"].(map[string]any)
	assert.Equal(t, "j-42", meta["jobID"],
		"client-supplied metadata fields outside `tags` must survive")
	tags := meta["tags"].([]any)
	require.Len(t, tags, 1)
	assert.Equal(t, "grp-eng", tags[0],
		"our tags overwrite any client-supplied metadata.tags so spoofing is impossible")
}

// TestInject_BodyTags_SkipsHostileMetadataShape pins the defensive
// refusal: when the request body has a non-object metadata field
// (string/number/array), we don't inject — header path still emits.
func TestInject_BodyTags_SkipsHostileMetadataShape(t *testing.T) {
	mw := New(Config{Providers: []ProviderInjection{liteLLMRuleWithBody()}})
	in := newInput(litellmProvider, "alice", []string{"grp-eng"})
	in.Body = []byte(`{"model":"gpt-4o-mini","metadata":"not-an-object"}`)

	out, err := mw.Invoke(context.Background(), in)
	require.NoError(t, err)
	require.NotNil(t, out.Mutations)
	assert.Empty(t, out.Mutations.BodyReplace,
		"non-object metadata must skip body inject (don't clobber)")

	for _, kv := range out.Mutations.HeadersAdd {
		if kv.Key == "x-litellm-tags" {
			assert.Equal(t, "grp-eng", kv.Value,
				"header path must still emit so spend tracking keeps working")
			return
		}
	}
	t.Fatalf("expected x-litellm-tags header even when body inject was skipped")
}

// TestInject_BodyTags_SkipsTruncatedBody pins that we don't blindly
// rewrite a body we don't have in full. The header path still runs.
func TestInject_BodyTags_SkipsTruncatedBody(t *testing.T) {
	mw := New(Config{Providers: []ProviderInjection{liteLLMRuleWithBody()}})
	in := newInput(litellmProvider, "alice", []string{"grp-eng"})
	in.Body = []byte(`{"model":"gpt-4o-mini","messages":[]}`)
	in.BodyTruncated = true

	out, err := mw.Invoke(context.Background(), in)
	require.NoError(t, err)
	assert.Empty(t, out.Mutations.BodyReplace,
		"truncated body must skip body inject — re-marshaling would corrupt the request")
}

// TestInject_BodyTags_SkipsNonJSONBody pins graceful behavior when the
// body isn't JSON (e.g. a streaming binary or form upload sneaking
// through the LLM chain). Header path still runs.
func TestInject_BodyTags_SkipsNonJSONBody(t *testing.T) {
	mw := New(Config{Providers: []ProviderInjection{liteLLMRuleWithBody()}})
	in := newInput(litellmProvider, "alice", []string{"grp-eng"})
	in.Body = []byte(`not even close to json`)

	out, err := mw.Invoke(context.Background(), in)
	require.NoError(t, err)
	assert.Empty(t, out.Mutations.BodyReplace,
		"non-JSON body must skip body inject silently")
}

// liteLLMRuleFull mirrors the catalog default: header path + body
// metadata.tags (groups) + body user (end-user id).
func liteLLMRuleFull() ProviderInjection {
	return ProviderInjection{
		ProviderID: litellmProvider,
		HeaderPair: &HeaderPairRule{
			EndUserIDHeader: "x-litellm-end-user-id",
			TagsHeader:      "x-litellm-tags",
			TagsInBody:      true,
			EndUserIDInBody: true,
		},
	}
}

// TestInject_BodyUser_WritesTopLevelUser pins the EndUserIDInBody path
// alone: body's top-level "user" field carries the display identity.
// Tags-in-body is OFF here so we isolate the user write.
func TestInject_BodyUser_WritesTopLevelUser(t *testing.T) {
	mw := New(Config{Providers: []ProviderInjection{{
		ProviderID: litellmProvider,
		HeaderPair: &HeaderPairRule{
			EndUserIDHeader: "x-litellm-end-user-id",
			EndUserIDInBody: true,
		},
	}}})
	in := newInput(litellmProvider, "alice", nil)
	in.UserEmail = "alice@example.com"
	in.Body = []byte(`{"model":"gpt-4o-mini","messages":[]}`)

	out, err := mw.Invoke(context.Background(), in)
	require.NoError(t, err)
	require.NotNil(t, out.Mutations)
	require.NotEmpty(t, out.Mutations.BodyReplace)

	var doc map[string]any
	require.NoError(t, json.Unmarshal(out.Mutations.BodyReplace, &doc))
	assert.Equal(t, "alice@example.com", doc["user"],
		"body's top-level user field must carry the display identity")
	_, hasMeta := doc["metadata"]
	assert.False(t, hasMeta, "TagsInBody is off; metadata must not be added")
}

// TestInject_BodyUser_OverwritesClientSupplied pins anti-spoof: a
// client-supplied "user" in the body is overwritten so the gateway
// only sees our trusted identity.
func TestInject_BodyUser_OverwritesClientSupplied(t *testing.T) {
	mw := New(Config{Providers: []ProviderInjection{liteLLMRuleFull()}})
	in := newInput(litellmProvider, "alice", []string{"grp-eng"})
	in.UserEmail = "alice@example.com"
	in.Body = []byte(`{"model":"gpt-4o-mini","user":"ceo@company.com"}`)

	out, err := mw.Invoke(context.Background(), in)
	require.NoError(t, err)
	require.NotEmpty(t, out.Mutations.BodyReplace)

	var doc map[string]any
	require.NoError(t, json.Unmarshal(out.Mutations.BodyReplace, &doc))
	assert.Equal(t, "alice@example.com", doc["user"],
		"client-supplied user must be overwritten with the trusted identity")
}

// TestInject_BodyCombined_TagsAndUser pins that with both flags on,
// the body carries both metadata.tags AND top-level user, and the
// header path still emits.
func TestInject_BodyCombined_TagsAndUser(t *testing.T) {
	mw := New(Config{Providers: []ProviderInjection{liteLLMRuleFull()}})
	in := newInput(litellmProvider, "alice", []string{"grp-eng", "grp-sre"})
	in.UserEmail = "alice@example.com"
	in.Body = []byte(`{"model":"gpt-4o-mini"}`)

	out, err := mw.Invoke(context.Background(), in)
	require.NoError(t, err)
	require.NotEmpty(t, out.Mutations.BodyReplace)

	var doc map[string]any
	require.NoError(t, json.Unmarshal(out.Mutations.BodyReplace, &doc))
	assert.Equal(t, "alice@example.com", doc["user"])
	meta := doc["metadata"].(map[string]any)
	tags := meta["tags"].([]any)
	require.Len(t, tags, 2)
	assert.Equal(t, "grp-eng", tags[0])
	assert.Equal(t, "grp-sre", tags[1])

	// Header path still emits — header end-user-id is the primary
	// path for LiteLLM's resolver, body is defense-in-depth.
	added := map[string]string{}
	for _, kv := range out.Mutations.HeadersAdd {
		added[kv.Key] = kv.Value
	}
	assert.Equal(t, "alice@example.com", added["x-litellm-end-user-id"])
	assert.Equal(t, "grp-eng,grp-sre", added["x-litellm-tags"])
}

// TestInject_BodyCombined_HostileMetadataKeepsUser pins the partial-
// success path: a hostile (non-object) metadata field skips the tag
// write but still allows the orthogonal user write to land.
func TestInject_BodyCombined_HostileMetadataKeepsUser(t *testing.T) {
	mw := New(Config{Providers: []ProviderInjection{liteLLMRuleFull()}})
	in := newInput(litellmProvider, "alice", []string{"grp-eng"})
	in.UserEmail = "alice@example.com"
	in.Body = []byte(`{"model":"gpt-4o-mini","metadata":"not-an-object"}`)

	out, err := mw.Invoke(context.Background(), in)
	require.NoError(t, err)
	require.NotEmpty(t, out.Mutations.BodyReplace,
		"user write must still go through even when metadata is hostile")

	var doc map[string]any
	require.NoError(t, json.Unmarshal(out.Mutations.BodyReplace, &doc))
	assert.Equal(t, "alice@example.com", doc["user"])
	assert.Equal(t, "not-an-object", doc["metadata"],
		"hostile metadata must be left untouched, not clobbered")
}

// TestInject_ExtraHeaders_Stamped pins the extras path: with a
// per-provider ExtraHeader configured (e.g. Portkey config id), the
// middleware stamps it on every matching request and adds the same
// name to HeadersRemove for anti-spoof.
func TestInject_ExtraHeaders_Stamped(t *testing.T) {
	mw := New(Config{Providers: []ProviderInjection{{
		ProviderID: portkeyProvider,
		JSONMetadata: &JSONMetadataRule{
			Header:    "x-portkey-metadata",
			UserKey:   "_user",
			GroupsKey: "groups",
		},
		ExtraHeaders: []ExtraHeaderKV{
			{Name: "x-portkey-config", Value: "pc-prod-3f2a"},
		},
	}}})
	in := newInput(portkeyProvider, "alice", []string{"grp-eng"})
	in.UserEmail = "alice@example.com"

	out, err := mw.Invoke(context.Background(), in)
	require.NoError(t, err)
	require.NotNil(t, out.Mutations)

	assert.Contains(t, out.Mutations.HeadersRemove, "x-portkey-config",
		"extras must be stripped before stamping for anti-spoof")
	added := map[string]string{}
	for _, kv := range out.Mutations.HeadersAdd {
		added[kv.Key] = kv.Value
	}
	assert.Equal(t, "pc-prod-3f2a", added["x-portkey-config"],
		"extras must carry the operator-configured value verbatim")
	// Identity-stamping shape (JSONMetadata header) still emitted.
	assert.Contains(t, added, "x-portkey-metadata",
		"extras and identity stamping are independent — both must land")
}

// TestInject_ExtraHeaders_OnlyRule pins that an extras-only rule
// (no HeaderPair, no JSONMetadata) survives New() and stamps the
// extras anyway. Useful for hypothetical gateways that need a static
// routing header but no NetBird identity stamping.
func TestInject_ExtraHeaders_OnlyRule(t *testing.T) {
	mw := New(Config{Providers: []ProviderInjection{{
		ProviderID: "ainp_extras-only",
		ExtraHeaders: []ExtraHeaderKV{
			{Name: "x-routing-key", Value: "rk-1"},
		},
	}}})
	in := newInput("ainp_extras-only", "alice", nil)

	out, err := mw.Invoke(context.Background(), in)
	require.NoError(t, err)
	require.NotNil(t, out.Mutations,
		"extras alone keep the rule alive — middleware must emit them")
	added := map[string]string{}
	for _, kv := range out.Mutations.HeadersAdd {
		added[kv.Key] = kv.Value
	}
	assert.Equal(t, "rk-1", added["x-routing-key"])
}

// TestInject_ExtraHeaders_EmptyValueSkipped pins that empty values are
// dropped silently (the synth would normally not send them, but the
// middleware is defensive).
func TestInject_ExtraHeaders_EmptyValueSkipped(t *testing.T) {
	mw := New(Config{Providers: []ProviderInjection{{
		ProviderID: portkeyProvider,
		JSONMetadata: &JSONMetadataRule{
			Header:  "x-portkey-metadata",
			UserKey: "_user",
		},
		ExtraHeaders: []ExtraHeaderKV{
			{Name: "x-portkey-config", Value: ""},
		},
	}}})
	in := newInput(portkeyProvider, "alice", []string{"grp-eng"})
	in.UserEmail = "alice@example.com"

	out, err := mw.Invoke(context.Background(), in)
	require.NoError(t, err)
	require.NotNil(t, out.Mutations)
	assert.NotContains(t, out.Mutations.HeadersRemove, "x-portkey-config",
		"empty extra value must not even strip the header")
	for _, kv := range out.Mutations.HeadersAdd {
		assert.NotEqual(t, "x-portkey-config", kv.Key,
			"empty extra value must not be stamped")
	}
}
