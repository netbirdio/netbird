package llm_limit_check

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

// callTimeout caps the wall-clock budget for the pre-flight RPC. The
// middleware sits on the request leg, so a slow management call
// translates directly to user-visible latency. 2s is loose enough for
// a healthy management cluster but tight enough that a stalled call
// fails open via the same path nil-MgmtClient does — an enforcement
// gate that adds 30s of latency is worse than a stale gate.
const callTimeout = 2 * time.Second

// Middleware is the per-target instance that runs the pre-flight check.
type Middleware struct {
	mgmt   builtin.MgmtClient
	logger *log.Logger
}

// New constructs a Middleware. mgmt may be nil — that's the
// no-management-wired case where the middleware is a pass-through
// (allow without attribution); useful for unit tests and for
// progressive rollout of the management RPC.
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

// Slot reports the chain slot the middleware lives in.
func (m *Middleware) Slot() middleware.Slot { return middleware.SlotOnRequest }

// AcceptedContentTypes returns nil because the gate consults metadata
// emitted upstream (KeyLLMResolvedProviderID) and never inspects bodies.
func (m *Middleware) AcceptedContentTypes() []string { return nil }

// MetadataKeys is the closed allowlist of keys this middleware emits.
func (m *Middleware) MetadataKeys() []string {
	return []string{
		middleware.KeyLLMSelectedPolicyID,
		middleware.KeyLLMAttributionGroupID,
		middleware.KeyLLMAttributionWindowS,
		middleware.KeyLLMPolicyDecision,
		middleware.KeyLLMPolicyReason,
	}
}

// MutationsSupported reports that the middleware never mutates the
// request body or headers; the only outcome is allow + metadata or
// deny.
func (m *Middleware) MutationsSupported() bool { return false }

// Close releases resources owned by the middleware. Stateless, so
// this is a no-op.
func (m *Middleware) Close() error { return nil }

// Invoke runs the pre-flight policy check.
func (m *Middleware) Invoke(ctx context.Context, in *middleware.Input) (*middleware.Output, error) {
	if m.mgmt == nil {
		// No management client wired — fall through to allow with
		// no attribution. RecordLLMUsage on the response leg will
		// also be a no-op so counters stay at zero. This matches
		// the PR1 behaviour exactly so a partial wiring is
		// indistinguishable from "no enforcement".
		return allowNoAttribution(), nil
	}

	providerID := lookupKV(in.Metadata, middleware.KeyLLMResolvedProviderID)
	if providerID == "" {
		// llm_router didn't emit a resolved provider id — usually
		// because the request didn't carry an llm.model. The
		// router itself denied; we won't reach here in production,
		// but defensively pass through so we never deny on top of
		// an upstream allow.
		return allowNoAttribution(), nil
	}

	rpcCtx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()

	resp, err := m.mgmt.CheckLLMPolicyLimits(rpcCtx, &proto.CheckLLMPolicyLimitsRequest{
		AccountId:  in.AccountID,
		UserId:     in.UserID,
		GroupIds:   append([]string(nil), in.UserGroups...),
		ProviderId: providerID,
		Model:      lookupKV(in.Metadata, middleware.KeyLLMModel),
	})
	if err != nil {
		// Fail-open on transport / management errors. The
		// alternative — denying every request when management is
		// unreachable — is worse for v1 (operational outage =
		// total LLM outage). Operators can audit via the
		// access-log; PR3 can switch to fail-closed under a flag.
		m.logger.WithError(err).
			WithField("middleware", ID).
			Debugf("management pre-flight failed; failing open")
		return allowNoAttribution(), nil
	}

	if resp.GetDecision() == "deny" {
		return denyFromManagement(resp), nil
	}
	return allowFromManagement(resp), nil
}

// allowNoAttribution returns the no-op allow envelope used when no
// management client is wired or no provider was resolved. Stamps
// decision=allow but no policy / attribution metadata so
// llm_limit_record skips its post-flight write.
func allowNoAttribution() *middleware.Output {
	return &middleware.Output{
		Decision: middleware.DecisionAllow,
		Metadata: []middleware.KV{
			{Key: middleware.KeyLLMPolicyDecision, Value: "allow"},
		},
	}
}

// allowFromManagement converts a successful CheckLLMPolicyLimits
// response into the chain's allow envelope, stamping the attribution
// metadata the response leg consumes.
func allowFromManagement(resp *proto.CheckLLMPolicyLimitsResponse) *middleware.Output {
	out := &middleware.Output{
		Decision: middleware.DecisionAllow,
		Metadata: []middleware.KV{
			{Key: middleware.KeyLLMPolicyDecision, Value: "allow"},
		},
	}
	if id := resp.GetSelectedPolicyId(); id != "" {
		out.Metadata = append(out.Metadata, middleware.KV{Key: middleware.KeyLLMSelectedPolicyID, Value: id})
	}
	if g := resp.GetAttributionGroupId(); g != "" {
		out.Metadata = append(out.Metadata, middleware.KV{Key: middleware.KeyLLMAttributionGroupID, Value: g})
	}
	if w := resp.GetWindowSeconds(); w > 0 {
		out.Metadata = append(out.Metadata, middleware.KV{Key: middleware.KeyLLMAttributionWindowS, Value: strconv.FormatInt(w, 10)})
	}
	return out
}

// denyFromManagement converts a deny response into the chain's deny
// envelope. The deny code surfaces verbatim through the framework's
// fixed JSON template; arbitrary middleware bytes can't reach the
// wire.
func denyFromManagement(resp *proto.CheckLLMPolicyLimitsResponse) *middleware.Output {
	code := resp.GetDenyCode()
	if code == "" {
		code = "llm_policy.cap_exceeded"
	}
	// The canonical code is safe to surface; the management-supplied
	// reason can name internal quota details (used amounts, caps, rule
	// ids), so keep the public message generic and leave the detail to
	// server-side logs.
	return &middleware.Output{
		Decision:   middleware.DecisionDeny,
		DenyStatus: 403,
		DenyReason: &middleware.DenyReason{
			Code:    code,
			Message: "LLM policy limit exceeded",
		},
		Metadata: []middleware.KV{
			{Key: middleware.KeyLLMPolicyDecision, Value: "deny"},
			{Key: middleware.KeyLLMPolicyReason, Value: code},
		},
	}
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
