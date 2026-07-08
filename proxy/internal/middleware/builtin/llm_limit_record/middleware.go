package llm_limit_record

import (
	"context"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/proxy/internal/middleware"
	"github.com/netbirdio/netbird/proxy/internal/middleware/builtin"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// Version is reported via Middleware.Version().
const Version = "1.0.0"

// callTimeout caps the wall-clock budget for the post-flight RPC.
// Longer than the pre-flight gate because this runs after the
// upstream returned and is not on the user-facing latency path —
// a slow record is just a delayed counter increment, not a delayed
// response to the caller.
const callTimeout = 5 * time.Second

// Middleware posts token + cost deltas to management after a served
// request. Stateless; per-call values come entirely from metadata
// emitted upstream.
type Middleware struct {
	mgmt   builtin.MgmtClient
	logger *log.Logger
}

// New constructs a Middleware bound to the supplied management
// client. mgmt may be nil — that disables the write entirely so a
// partially wired environment doesn't attempt to dial nothing.
func New(mgmt builtin.MgmtClient, logger *log.Logger) *Middleware {
	if logger == nil {
		logger = log.StandardLogger()
	}
	return &Middleware{mgmt: mgmt, logger: logger}
}

// ID returns the registry identifier.
func (m *Middleware) ID() string { return ID }

// Version returns the implementation version.
func (m *Middleware) Version() string { return Version }

// Slot reports that the middleware runs after the upstream call.
func (m *Middleware) Slot() middleware.Slot { return middleware.SlotOnResponse }

// AcceptedContentTypes is empty: this middleware never inspects
// bodies. It only reads metadata emitted upstream.
func (m *Middleware) AcceptedContentTypes() []string { return []string{} }

// MetadataKeys is empty — the record middleware never emits its own
// metadata. Its only side effect is the gRPC write to management.
func (m *Middleware) MetadataKeys() []string { return []string{} }

// MutationsSupported reports that the middleware never mutates the
// response. Its outcome is always Allow.
func (m *Middleware) MutationsSupported() bool { return false }

// Close releases resources owned by the middleware. Stateless.
func (m *Middleware) Close() error { return nil }

// Invoke reads the attribution + tokens + cost metadata, calls
// management's RecordLLMUsage, and always returns Allow. RPC errors
// are logged at debug level — the response has already been served
// to the client by the time we get here, so a record failure must
// not surface back through the proxy.
func (m *Middleware) Invoke(ctx context.Context, in *middleware.Input) (*middleware.Output, error) {
	out := &middleware.Output{Decision: middleware.DecisionAllow}
	if m.mgmt == nil {
		return out, nil
	}

	tokensIn, _ := strconv.ParseInt(lookupKV(in.Metadata, middleware.KeyLLMInputTokens), 10, 64)
	tokensOut, _ := strconv.ParseInt(lookupKV(in.Metadata, middleware.KeyLLMOutputTokens), 10, 64)
	costUSD, _ := strconv.ParseFloat(lookupKV(in.Metadata, middleware.KeyCostUSDTotal), 64)
	if tokensIn == 0 && tokensOut == 0 && costUSD == 0 {
		// llm_response_parser couldn't read usage off the upstream
		// response (streaming-not-yet-supported, malformed body, …).
		// Skipping the write keeps phantom rows out of the
		// consumption table.
		return out, nil
	}

	windowStr := lookupKV(in.Metadata, middleware.KeyLLMAttributionWindowS)
	windowSeconds, _ := strconv.ParseInt(windowStr, 10, 64)
	groupID := lookupKV(in.Metadata, middleware.KeyLLMAttributionGroupID)

	// A zero attribution window means no policy cap bound this request (deny at
	// the gate, or a catch-all-allow policy). We still record so account-level
	// budget rules — which live in their own windows and bind independently of
	// policies — accumulate. The management side books the policy dimensions
	// only when window_seconds > 0 and fans out to account rules regardless.
	if in.UserID == "" && groupID == "" && len(in.UserGroups) == 0 {
		m.logger.WithField("middleware", ID).
			WithField("account_id", in.AccountID).
			Debugf("post-flight skipped: no user/group/groups to attribute (tokens=%d/%d cost=%g window=%d)", tokensIn, tokensOut, costUSD, windowSeconds)
		return out, nil
	}

	rpcCtx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()

	m.logger.WithField("middleware", ID).
		WithField("account_id", in.AccountID).
		WithField("user_id", in.UserID).
		WithField("group_id", groupID).
		WithField("group_ids_len", len(in.UserGroups)).
		Debugf("post-flight sending RecordLLMUsage (tokens=%d/%d cost=%g window=%d)", tokensIn, tokensOut, costUSD, windowSeconds)

	if _, err := m.mgmt.RecordLLMUsage(rpcCtx, &proto.RecordLLMUsageRequest{
		AccountId:     in.AccountID,
		UserId:        in.UserID,
		GroupId:       groupID,
		WindowSeconds: windowSeconds,
		TokensInput:   tokensIn,
		TokensOutput:  tokensOut,
		CostUsd:       costUSD,
		GroupIds:      append([]string(nil), in.UserGroups...),
	}); err != nil {
		m.logger.WithError(err).
			WithField("middleware", ID).
			WithField("account_id", in.AccountID).
			WithField("user_id", in.UserID).
			WithField("group_id", groupID).
			Debugf("post-flight record failed; counter will lag this request")
	}
	return out, nil
}

// lookupKV returns the value associated with key, or the empty
// string when absent.
func lookupKV(kvs []middleware.KV, key string) string {
	for _, kv := range kvs {
		if kv.Key == key {
			return kv.Value
		}
	}
	return ""
}
