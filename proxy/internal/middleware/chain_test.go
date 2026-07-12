package middleware

import (
	"context"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeMiddleware is a minimal Middleware for chain composition tests.
// It records the metadata the dispatcher hands to it and emits a
// caller-supplied Output. Tests use the recorded snapshot to assert
// that earlier-in-slot emissions are visible to later middlewares.
type fakeMiddleware struct {
	id                 string
	slot               Slot
	keys               []string
	emit               []KV
	decision           Decision
	mutationsSupported bool
	canMutate          bool
	mutations          *Mutations

	// seen captures the in.Metadata snapshot the dispatcher passed to
	// Invoke, so tests can assert ordering and visibility.
	seen []KV
}

func (f *fakeMiddleware) ID() string                     { return f.id }
func (f *fakeMiddleware) Version() string                { return "test" }
func (f *fakeMiddleware) Slot() Slot                     { return f.slot }
func (f *fakeMiddleware) AcceptedContentTypes() []string { return nil }
func (f *fakeMiddleware) MetadataKeys() []string         { return f.keys }
func (f *fakeMiddleware) MutationsSupported() bool       { return f.mutationsSupported }
func (f *fakeMiddleware) Close() error                   { return nil }

func (f *fakeMiddleware) Invoke(_ context.Context, in *Input) (*Output, error) {
	f.seen = append([]KV(nil), in.Metadata...)
	out := &Output{Decision: f.decision, Metadata: append([]KV(nil), f.emit...)}
	if f.mutations != nil {
		m := *f.mutations
		out.Mutations = &m
	}
	return out, nil
}

// chainFor builds a Chain over the given middlewares with a noop
// dispatcher.
func chainFor(t *testing.T, mws ...*fakeMiddleware) *Chain {
	t.Helper()
	bound := make([]boundMiddleware, len(mws))
	for i, mw := range mws {
		bound[i] = boundMiddleware{
			spec: Spec{
				ID:                 mw.id,
				Slot:               mw.slot,
				Enabled:            true,
				MetadataKeys:       mw.keys,
				CanMutate:          mw.canMutate,
				MutationsSupported: mw.mutationsSupported,
			},
			mw: mw,
		}
	}
	disp := NewDispatcher(nil, nil)
	return NewChain("t-1", bound, disp)
}

// TestChain_RunRequest_ThreadsMetadataAcrossMiddlewares locks that
// each on_request middleware sees metadata emitted by earlier
// middlewares in the same slot. Regression cover for the original
// chain.go where every iteration cloned from the same source `in` and
// later middlewares (e.g. llm_guardrail) couldn't read what the first
// (e.g. llm_request_parser) had just emitted.
func TestChain_RunRequest_ThreadsMetadataAcrossMiddlewares(t *testing.T) {
	first := &fakeMiddleware{
		id:   "first",
		slot: SlotOnRequest,
		keys: []string{"foo.k"},
		emit: []KV{{Key: "foo.k", Value: "v"}},
	}
	second := &fakeMiddleware{
		id:   "second",
		slot: SlotOnRequest,
		keys: []string{"bar.k"},
		emit: []KV{{Key: "bar.k", Value: "z"}},
	}
	c := chainFor(t, first, second)
	acc := NewAccumulator(0)

	denied, merged, rewrite, err := c.RunRequest(context.Background(), nil, &Input{}, acc)
	require.NoError(t, err)
	assert.Nil(t, denied, "no deny without DecisionDeny")
	assert.Nil(t, rewrite, "no rewrite without Mutations.RewriteUpstream")

	require.Len(t, second.seen, 1, "the second middleware must observe one prior emission")
	assert.Equal(t, "foo.k", second.seen[0].Key, "second middleware must see the first middleware's key")
	assert.Equal(t, "v", second.seen[0].Value, "second middleware must see the first middleware's value")

	require.Len(t, merged, 2, "merged slice contains both middleware emissions")
}

// TestChain_RunResponse_ThreadsMetadataAcrossMiddlewares does the
// same for the response slot. The response slot iterates in reverse
// registration order, so the middleware registered LAST runs first.
// This test asserts that a middleware running later (in reverse
// order) sees the metadata emitted by the one that ran before it.
func TestChain_RunResponse_ThreadsMetadataAcrossMiddlewares(t *testing.T) {
	// Registration order: [outer, inner].
	// Reverse iteration runs inner first, outer second.
	// outer must see inner's emission.
	outer := &fakeMiddleware{
		id:   "outer",
		slot: SlotOnResponse,
		keys: []string{"outer.k"},
		emit: []KV{{Key: "outer.k", Value: "o"}},
	}
	inner := &fakeMiddleware{
		id:   "inner",
		slot: SlotOnResponse,
		keys: []string{"inner.k"},
		emit: []KV{{Key: "inner.k", Value: "i"}},
	}
	c := chainFor(t, outer, inner)
	acc := NewAccumulator(0)

	merged := c.RunResponse(context.Background(), &Input{}, acc)

	require.Len(t, outer.seen, 1, "outer must observe inner's emission")
	assert.Equal(t, "inner.k", outer.seen[0].Key)
	require.Len(t, merged, 2, "merged slice contains both response emissions")
}

// TestChain_RunResponse_CostMeterScenario simulates the synth-service
// chain shape (response_parser registered AFTER cost_meter so reverse
// iter runs response_parser first). The cost_meter analogue must see
// the tokens response_parser just emitted — this is the exact
// regression that produced cost.skipped=missing_tokens in the live
// access logs.
func TestChain_RunResponse_CostMeterScenario(t *testing.T) {
	// Synthesizer registers cost_meter first, response_parser second.
	costMeter := &fakeMiddleware{
		id:   "cost_meter",
		slot: SlotOnResponse,
		keys: []string{"cost.usd_total", "cost.skipped"},
	}
	respParser := &fakeMiddleware{
		id:   "llm_response_parser",
		slot: SlotOnResponse,
		keys: []string{"llm.input_tokens", "llm.output_tokens"},
		emit: []KV{
			{Key: "llm.input_tokens", Value: "13"},
			{Key: "llm.output_tokens", Value: "259"},
		},
	}
	c := chainFor(t, costMeter, respParser)
	acc := NewAccumulator(0)

	_ = c.RunResponse(context.Background(), &Input{}, acc)

	require.Len(t, costMeter.seen, 2, "cost_meter must observe both token keys emitted by response_parser")
	keys := []string{costMeter.seen[0].Key, costMeter.seen[1].Key}
	assert.ElementsMatch(t, []string{"llm.input_tokens", "llm.output_tokens"}, keys,
		"cost_meter must see the exact keys response_parser emitted")
	values := []string{costMeter.seen[0].Value, costMeter.seen[1].Value}
	assert.ElementsMatch(t, []string{"13", "259"}, values, "cost_meter must see the exact token counts")
	for _, kv := range costMeter.seen {
		_, err := strconv.Atoi(kv.Value)
		assert.NoError(t, err, "values handed to cost_meter must be numeric (regression for missing_tokens)")
	}
}

// TestChain_RunResponse_DetachedContextStillRecords guards the metering
// fix in reverseproxy.go. The response/terminal phase runs after the body
// is forwarded, so a streaming client has usually disconnected by then,
// cancelling its request context. The dispatcher derives each middleware's
// context from the one passed here and short-circuits to fail-mode the
// instant it's Done, which silently drops token/cost metering. The reverse
// proxy now detaches that phase with context.WithoutCancel; this proves a
// context detached from an already-cancelled parent still lets a response
// middleware emit. (The cancelled-parent direction is intentionally not
// asserted: the dispatcher's select over ctx.Done vs the result channel is
// racy when both are ready, which is exactly why the bug was intermittent.)
func TestChain_RunResponse_DetachedContextStillRecords(t *testing.T) {
	resp := &fakeMiddleware{
		id:       "recorder",
		slot:     SlotOnResponse,
		keys:     []string{"llm.input_tokens"},
		emit:     []KV{{Key: "llm.input_tokens", Value: "42"}},
		decision: DecisionPassthrough,
	}
	c := chainFor(t, resp)

	clientCtx, cancel := context.WithCancel(context.Background())
	cancel() // client disconnected after the stream completed
	require.Error(t, clientCtx.Err(), "client context must be cancelled for the test to be meaningful")

	detached := context.WithoutCancel(clientCtx)
	require.NoError(t, detached.Err(), "detached context must not inherit the client's cancellation")

	acc := NewAccumulator(MaxRequestMetadataBytes)
	merged := c.RunResponse(detached, &Input{Slot: SlotOnResponse}, acc)

	var got string
	for _, kv := range merged {
		if kv.Key == "llm.input_tokens" {
			got = kv.Value
		}
	}
	assert.Equal(t, "42", got, "response middleware must still emit token metadata under the detached context")
}

// TestChain_RunRequest_LatestRewriteWins asserts that when two
// on_request middlewares both emit an UpstreamRewrite, the chain
// returns the value from the later middleware.
func TestChain_RunRequest_LatestRewriteWins(t *testing.T) {
	first := &fakeMiddleware{
		id:                 "first",
		slot:               SlotOnRequest,
		mutationsSupported: true,
		canMutate:          true,
		mutations:          &Mutations{RewriteUpstream: &UpstreamRewrite{Scheme: "https", Host: "first.test"}},
	}
	second := &fakeMiddleware{
		id:                 "second",
		slot:               SlotOnRequest,
		mutationsSupported: true,
		canMutate:          true,
		mutations:          &Mutations{RewriteUpstream: &UpstreamRewrite{Scheme: "https", Host: "second.test"}},
	}
	c := chainFor(t, first, second)
	acc := NewAccumulator(0)

	denied, _, rewrite, err := c.RunRequest(context.Background(), nil, &Input{}, acc)
	require.NoError(t, err)
	assert.Nil(t, denied, "neither middleware denies")
	require.NotNil(t, rewrite, "chain must surface the rewrite emitted by the on_request slot")
	assert.Equal(t, "https", rewrite.Scheme, "rewrite scheme must come from the later middleware")
	assert.Equal(t, "second.test", rewrite.Host, "rewrite host must come from the later middleware (last-write-wins)")
}

// TestChain_RunRequest_NoRewrite_NilReturn asserts the chain returns a
// nil rewrite when no middleware emits one.
func TestChain_RunRequest_NoRewrite_NilReturn(t *testing.T) {
	first := &fakeMiddleware{id: "first", slot: SlotOnRequest}
	second := &fakeMiddleware{id: "second", slot: SlotOnRequest}
	c := chainFor(t, first, second)
	acc := NewAccumulator(0)

	denied, _, rewrite, err := c.RunRequest(context.Background(), nil, &Input{}, acc)
	require.NoError(t, err)
	assert.Nil(t, denied, "neither middleware denies")
	assert.Nil(t, rewrite, "chain must return nil rewrite when no middleware emits one")
}

// TestChain_ApplyMutations_RewriteGatedOnCanMutate asserts that a
// middleware emitting an UpstreamRewrite with CanMutate=false has its
// rewrite filtered out by the chain. The dispatcher's filterOutput
// already clears Mutations when the gates fail; the chain's defensive
// gate inside mutationRewrite mirrors that contract so a stale
// Mutations field cannot leak through.
func TestChain_ApplyMutations_RewriteGatedOnCanMutate(t *testing.T) {
	mw := &fakeMiddleware{
		id:                 "first",
		slot:               SlotOnRequest,
		mutationsSupported: true,
		canMutate:          false,
		mutations:          &Mutations{RewriteUpstream: &UpstreamRewrite{Scheme: "https", Host: "denied.test"}},
	}
	c := chainFor(t, mw)
	acc := NewAccumulator(0)

	denied, _, rewrite, err := c.RunRequest(context.Background(), nil, &Input{}, acc)
	require.NoError(t, err)
	assert.Nil(t, denied, "middleware does not deny")
	assert.Nil(t, rewrite, "rewrite must be filtered when CanMutate=false")
}

// TestChain_RunRequest_PropagatesUserGroups asserts the chain forwards
// Input.UserGroups verbatim through cloneInputFor so policy-aware
// middlewares (e.g. llm_policy_check) can authorise without an extra
// management round-trip.
func TestChain_RunRequest_PropagatesUserGroups(t *testing.T) {
	groupCapture := &userGroupCaptureMiddleware{
		id:   "group-capture",
		slot: SlotOnRequest,
	}
	c := chainFor(t, groupCapture.fake())
	groupCapture.bind(c)
	acc := NewAccumulator(0)

	in := &Input{UserGroups: []string{"g1"}}
	denied, _, _, err := c.RunRequest(context.Background(), nil, in, acc)
	require.NoError(t, err)
	assert.Nil(t, denied, "no deny without DecisionDeny")

	require.Len(t, groupCapture.seenGroups, 1, "middleware must observe the caller's UserGroups")
	assert.Equal(t, "g1", groupCapture.seenGroups[0], "UserGroups must reach the middleware verbatim")
}

// userGroupCaptureMiddleware is a fakeMiddleware variant that records
// Input.UserGroups during Invoke. It exists so the cloneInputFor
// behaviour for the new field can be asserted without leaking into
// every other chain test.
type userGroupCaptureMiddleware struct {
	id         string
	slot       Slot
	seenGroups []string
	fakeMW     *fakeMiddleware
}

func (u *userGroupCaptureMiddleware) fake() *fakeMiddleware {
	u.fakeMW = &fakeMiddleware{id: u.id, slot: u.slot}
	return u.fakeMW
}

func (u *userGroupCaptureMiddleware) bind(c *Chain) {
	for i, bm := range c.all {
		if bm.spec.ID != u.id {
			continue
		}
		c.all[i].mw = userGroupRecorder{
			fakeMiddleware: u.fakeMW,
			parent:         u,
		}
	}
}

type userGroupRecorder struct {
	*fakeMiddleware
	parent *userGroupCaptureMiddleware
}

func (r userGroupRecorder) Invoke(ctx context.Context, in *Input) (*Output, error) {
	r.parent.seenGroups = append([]string(nil), in.UserGroups...)
	return r.fakeMiddleware.Invoke(ctx, in)
}

// TestChain_RunTerminal_SeesAccumulatedMetadata locks that terminal
// middlewares observe the full bag (the caller-supplied in.Metadata
// plus any prior terminal emissions).
func TestChain_RunTerminal_SeesAccumulatedMetadata(t *testing.T) {
	first := &fakeMiddleware{
		id:   "term-1",
		slot: SlotTerminal,
		keys: []string{"term.first"},
		emit: []KV{{Key: "term.first", Value: "1"}},
	}
	second := &fakeMiddleware{
		id:   "term-2",
		slot: SlotTerminal,
		keys: []string{"term.second"},
	}
	c := chainFor(t, first, second)
	acc := NewAccumulator(0)

	in := &Input{Metadata: []KV{{Key: "ext.k", Value: "ext"}}}
	merged := c.RunTerminal(context.Background(), in, acc)

	require.Len(t, second.seen, 2, "second terminal must see ext bag + first terminal's emission")
	got := map[string]string{}
	for _, kv := range second.seen {
		got[kv.Key] = kv.Value
	}
	assert.Equal(t, "ext", got["ext.k"], "external bag carries through")
	assert.Equal(t, "1", got["term.first"], "first terminal's emission visible to second terminal")
	assert.Len(t, merged, 1, "only first terminal emitted; second emitted nothing")
}
