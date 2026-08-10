package middleware

import (
	"context"
	"net/http"
	"sync"
)

// boundMiddleware pairs a validated spec with the resolved middleware
// instance the chain will invoke.
type boundMiddleware struct {
	spec Spec
	mw   Middleware
}

// Chain is the ordered set of middlewares that run for a specific
// target. Chains are immutable once built; Manager produces a new
// Chain on every Rebuild.
//
// Ordering: middlewares are kept in registration order. RunRequest
// iterates the SlotOnRequest middlewares in order; RunResponse
// iterates the SlotOnResponse middlewares in reverse order
// (middleware-style LIFO so the last to see the request is the first
// to see the response); RunTerminal iterates the SlotTerminal
// middlewares in registration order, after every on_response slot has
// emitted, so the metadata bag they observe is complete.
//
// Close drains in-flight invocations and tears down each middleware.
// Callers swapping a chain via Manager invoke Close on the old chain
// after the swap so live requests finish on the previous instance.
type Chain struct {
	targetID   string
	all        []boundMiddleware
	onRequest  []int
	onResponse []int
	terminal   []int
	dispatcher *Dispatcher
	inflight   sync.WaitGroup
}

// NewChain assembles a Chain from the bound middlewares. The slice
// order is the registration order; the chain captures index slices
// per slot so iteration does not re-scan the slot field per call.
func NewChain(targetID string, bound []boundMiddleware, d *Dispatcher) *Chain {
	c := &Chain{
		targetID:   targetID,
		all:        bound,
		dispatcher: d,
	}
	for i, bm := range bound {
		switch bm.spec.Slot {
		case SlotOnRequest:
			c.onRequest = append(c.onRequest, i)
		case SlotOnResponse:
			c.onResponse = append(c.onResponse, i)
		case SlotTerminal:
			c.terminal = append(c.terminal, i)
		}
	}
	return c
}

// Close waits for outstanding invocations against this chain to
// finish (bounded by ctx) and releases the middleware instances bound
// to it. Safe to call once the chain has been removed from the
// routing snapshot. Subsequent Run* calls are still safe (return
// without invoking) but Close itself is one-shot.
func (c *Chain) Close(ctx context.Context) error {
	if c == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	done := make(chan struct{})
	go func() {
		c.inflight.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		// Drain timed out: requests may still be running against these
		// middleware instances, so tearing them down now risks a
		// use-after-close. Leave them (a bounded leak) and surface the
		// timeout; the runaway backstop in the Manager already alerts.
		return ctx.Err()
	}
	for _, bm := range c.all {
		if bm.mw == nil {
			continue
		}
		if err := bm.mw.Close(); err != nil {
			c.dispatcher.logger.Debugf("middleware %s close: %v", bm.spec.ID, err)
		}
	}
	return nil
}

// Empty reports whether the chain has no middlewares.
func (c *Chain) Empty() bool {
	return c == nil || len(c.all) == 0
}

// TargetID returns the key used to find this chain.
func (c *Chain) TargetID() string {
	if c == nil {
		return ""
	}
	return c.targetID
}

// IDs returns the ordered list of middleware IDs bound to this chain.
func (c *Chain) IDs() []string {
	if c == nil {
		return nil
	}
	out := make([]string, len(c.all))
	for i, bm := range c.all {
		out[i] = bm.spec.ID
	}
	return out
}

// RunRequest iterates the on_request slot in registration order. Deny
// short-circuits the remaining middlewares and returns the deny
// output. The caller owns applying mutations to the real request and
// merging the metadata returned in `merged` into the captured-data
// bag passed to subsequent slots.
//
// Each middleware sees the metadata emitted by earlier middlewares in
// the same slot — this is how llm_guardrail reads
// llm.request_prompt_raw from llm_request_parser without a side
// channel, and how cost_meter reads tokens emitted by
// llm_response_parser on the response leg.
//
// If any middleware emits a non-nil Mutations.RewriteUpstream while
// satisfying the mutation gates (CanMutate && MutationsSupported), the
// latest such value is returned to the caller. Last-write-wins so the
// last middleware in the slot can override an earlier rewrite.
func (c *Chain) RunRequest(ctx context.Context, r *http.Request, in *Input, acc *Accumulator) (denied *Output, merged []KV, rewrite *UpstreamRewrite, err error) {
	if c.Empty() || len(c.onRequest) == 0 {
		return nil, nil, nil, nil
	}
	c.inflight.Add(1)
	defer c.inflight.Done()
	running := append([]KV(nil), in.Metadata...)
	for _, idx := range c.onRequest {
		bm := c.all[idx]
		call := cloneInputFor(in, SlotOnRequest)
		call.Metadata = append([]KV(nil), running...)
		out, invErr := c.dispatcher.Invoke(ctx, bm.spec, bm.mw, call)
		if invErr != nil && out == nil {
			continue
		}
		if out == nil {
			continue
		}

		accepted, rejected := acc.Emit(bm.spec.ID, bm.spec.MetadataKeys, out.Metadata)
		for _, rej := range rejected {
			c.dispatcher.metrics.IncMetadataRejected(ctx, bm.spec.ID, rej.Reason)
		}
		merged = append(merged, accepted...)
		running = append(running, accepted...)

		if out.Decision == DecisionDeny {
			c.dispatcher.metrics.IncRequest(ctx, bm.spec.ID, c.targetID, "deny")
			return out, merged, rewrite, nil
		}
		c.dispatcher.metrics.IncRequest(ctx, bm.spec.ID, c.targetID, "allow")

		if rw := mutationRewrite(bm.spec, out.Mutations); rw != nil {
			rewrite = rw
		}
		if r != nil && bm.spec.CanMutate && out.Mutations != nil {
			applyMutations(ctx, c.dispatcher, bm.spec, r, out.Mutations)
		}
	}
	return nil, merged, rewrite, nil
}

// RunResponse iterates the on_response slot in reverse registration
// order, matching the middleware "last in, first out" convention so
// the last middleware to see the request is the first to see the
// response. Middlewares cannot deny; they emit metadata.
//
// As with RunRequest, each middleware sees the metadata emitted by
// earlier middlewares in this slot — accumulated in the order the
// middlewares run (LIFO of registration). cost_meter relies on this
// to read llm.input_tokens / llm.output_tokens that
// llm_response_parser emitted just before it.
func (c *Chain) RunResponse(ctx context.Context, in *Input, acc *Accumulator) (merged []KV) {
	if c.Empty() || len(c.onResponse) == 0 {
		return nil
	}
	c.inflight.Add(1)
	defer c.inflight.Done()
	running := append([]KV(nil), in.Metadata...)
	for i := len(c.onResponse) - 1; i >= 0; i-- {
		bm := c.all[c.onResponse[i]]
		call := cloneInputFor(in, SlotOnResponse)
		call.Metadata = append([]KV(nil), running...)
		out, _ := c.dispatcher.Invoke(ctx, bm.spec, bm.mw, call)
		if out == nil {
			continue
		}
		accepted, rejected := acc.Emit(bm.spec.ID, bm.spec.MetadataKeys, out.Metadata)
		for _, rej := range rejected {
			c.dispatcher.metrics.IncMetadataRejected(ctx, bm.spec.ID, rej.Reason)
		}
		merged = append(merged, accepted...)
		running = append(running, accepted...)
		c.dispatcher.metrics.IncRequest(ctx, bm.spec.ID, c.targetID, "passthrough")
	}
	return merged
}

// RunTerminal iterates the terminal slot in registration order, after
// every on_response middleware has emitted. Terminal middlewares
// observe the full metadata bag carried in `in.Metadata` plus any
// emissions from terminal middlewares that ran before them; they
// cannot deny and cannot mutate.
func (c *Chain) RunTerminal(ctx context.Context, in *Input, acc *Accumulator) (merged []KV) {
	if c.Empty() || len(c.terminal) == 0 {
		return nil
	}
	c.inflight.Add(1)
	defer c.inflight.Done()
	running := append([]KV(nil), in.Metadata...)
	for _, idx := range c.terminal {
		bm := c.all[idx]
		call := cloneInputFor(in, SlotTerminal)
		call.Metadata = append([]KV(nil), running...)
		out, _ := c.dispatcher.Invoke(ctx, bm.spec, bm.mw, call)
		if out == nil {
			continue
		}
		accepted, rejected := acc.Emit(bm.spec.ID, bm.spec.MetadataKeys, out.Metadata)
		for _, rej := range rejected {
			c.dispatcher.metrics.IncMetadataRejected(ctx, bm.spec.ID, rej.Reason)
		}
		merged = append(merged, accepted...)
		running = append(running, accepted...)
		c.dispatcher.metrics.IncRequest(ctx, bm.spec.ID, c.targetID, "terminal")
	}
	return merged
}

// mutationRewrite returns the upstream rewrite carried in m when the
// spec's mutation gates allow it. The rewrite itself is not applied
// here; the caller (reverse proxy) decides whether to honour it.
func mutationRewrite(spec Spec, m *Mutations) *UpstreamRewrite {
	if m == nil || m.RewriteUpstream == nil {
		return nil
	}
	if !spec.CanMutate || !spec.MutationsSupported {
		return nil
	}
	return m.RewriteUpstream
}

func applyMutations(ctx context.Context, d *Dispatcher, spec Spec, r *http.Request, m *Mutations) {
	if m == nil {
		return
	}
	add, remove, blocked := FilterHeaderMutations(m)
	for _, h := range blocked {
		d.metrics.IncHeaderMutationBlocked(ctx, spec.ID, h)
	}
	for _, name := range remove {
		r.Header.Del(name)
	}
	for _, kv := range add {
		r.Header.Add(kv.Key, kv.Value)
	}
	if len(m.BodyReplace) == 0 {
		return
	}
	if err := ValidateBodyReplace(r, m.BodyReplace, true); err != nil {
		d.logger.Warnf("middleware %s body replace rejected: %v", spec.ID, err)
		return
	}
	ApplyBodyReplace(r, m.BodyReplace)
}

// cloneInputFor deep-copies the mutation-prone fields of Input so
// each middleware receives an isolated view.
func cloneInputFor(in *Input, slot Slot) *Input {
	if in == nil {
		return nil
	}
	out := *in
	out.Slot = slot
	out.Headers = cloneKVs(in.Headers)
	out.RespHeaders = cloneKVs(in.RespHeaders)
	out.Metadata = cloneKVs(in.Metadata)
	if len(in.UserGroups) > 0 {
		out.UserGroups = append([]string(nil), in.UserGroups...)
	}
	if len(in.UserGroupNames) > 0 {
		out.UserGroupNames = append([]string(nil), in.UserGroupNames...)
	}
	if len(in.Body) > 0 {
		out.Body = append([]byte(nil), in.Body...)
	}
	if len(in.RespBody) > 0 {
		out.RespBody = append([]byte(nil), in.RespBody...)
	}
	return &out
}

func cloneKVs(in []KV) []KV {
	if len(in) == 0 {
		return nil
	}
	out := make([]KV, len(in))
	copy(out, in)
	return out
}
