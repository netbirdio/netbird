package proxy

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/proxy/internal/middleware"
	"github.com/netbirdio/netbird/proxy/internal/middleware/bodytap"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// translateMiddlewareCaptureConfig builds the per-target capture
// limits used by the middleware chain. Returns nil when the options
// are nil or no capture field is set. Negative caps are normalised to
// zero; oversized caps are clamped to middleware.MaxBodyCapBytes.
func translateMiddlewareCaptureConfig(targetID string, opts *proto.PathTargetOptions) *bodytap.Config {
	if opts == nil {
		return nil
	}
	reqCap := clampMiddlewareCaptureBytes(targetID, "request", opts.GetCaptureMaxRequestBytes())
	respCap := clampMiddlewareCaptureBytes(targetID, "response", opts.GetCaptureMaxResponseBytes())
	types := opts.GetCaptureContentTypes()
	if reqCap == 0 && respCap == 0 && len(types) == 0 {
		return nil
	}
	return &bodytap.Config{
		MaxRequestBytes:  reqCap,
		MaxResponseBytes: respCap,
		ContentTypes:     types,
	}
}

func clampMiddlewareCaptureBytes(targetID, direction string, v int64) int64 {
	if v < 0 {
		log.Debugf("target %s %s capture cap %d clamped to 0", targetID, direction, v)
		return 0
	}
	if v > middleware.MaxBodyCapBytes {
		log.Debugf("target %s %s capture cap %d clamped to %d", targetID, direction, v, middleware.MaxBodyCapBytes)
		return middleware.MaxBodyCapBytes
	}
	return v
}

// translateMiddlewareConfigs converts the proto MiddlewareConfig list
// into validated middleware.Spec values. The list is truncated to
// middleware.MaxMiddlewaresPerChain when the caller exceeds the cap.
// Entries with empty IDs, unknown IDs (when registry is non-nil), or
// unspecified slots are skipped with a warn log. Timeouts are clamped
// to [MinTimeout, MaxTimeout] and zero substitutes for DefaultTimeout.
// Returns nil when the resulting slice is empty so callers can leave
// PathTarget.Middlewares unset.
func translateMiddlewareConfigs(
	ctx context.Context,
	targetID string,
	in []*proto.MiddlewareConfig,
	registry *middleware.Registry,
) []middleware.Spec {
	_ = ctx
	if len(in) == 0 {
		return nil
	}
	if len(in) > middleware.MaxMiddlewaresPerChain {
		log.Warnf("middleware list for target %q truncated: %d entries exceeds cap of %d",
			targetID, len(in), middleware.MaxMiddlewaresPerChain)
		in = in[:middleware.MaxMiddlewaresPerChain]
	}

	out := make([]middleware.Spec, 0, len(in))
	for _, cfg := range in {
		spec, ok := translateMiddlewareConfig(targetID, cfg, registry)
		if !ok {
			continue
		}
		out = append(out, spec)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// translateMiddlewareConfig validates and converts a single
// MiddlewareConfig. The second return value is false when the entry
// must be dropped from the chain.
func translateMiddlewareConfig(targetID string, cfg *proto.MiddlewareConfig, registry *middleware.Registry) (middleware.Spec, bool) {
	if cfg == nil {
		return middleware.Spec{}, false
	}
	id := cfg.GetId()
	if id == "" {
		log.Warnf("middleware config for target %q dropped: empty middleware id", targetID)
		return middleware.Spec{}, false
	}
	if registry != nil && !registry.IsKnown(id) {
		log.Warnf("unknown middleware %q configured for target %s; dropping", id, targetID)
		return middleware.Spec{}, false
	}
	slot, ok := protoToMiddlewareSlot(cfg.GetSlot())
	if !ok {
		log.Warnf("middleware %q on target %q dropped: slot is unspecified", id, targetID)
		return middleware.Spec{}, false
	}

	var rawConfig []byte
	if src := cfg.GetConfigJson(); len(src) > 0 {
		rawConfig = append([]byte(nil), src...)
	}

	return middleware.Spec{
		ID:        id,
		Slot:      slot,
		Enabled:   cfg.GetEnabled(),
		FailMode:  protoToMiddlewareFailMode(cfg.GetFailMode()),
		Timeout:   clampMiddlewareTimeout(id, cfg.GetTimeout().AsDuration()),
		RawConfig: rawConfig,
		CanMutate: cfg.GetCanMutate(),
	}, true
}

// protoToMiddlewareSlot maps the proto slot enum onto the internal
// middleware.Slot. Returns ok=false for the UNSPECIFIED value so the
// translator can drop the entry.
func protoToMiddlewareSlot(s proto.MiddlewareSlot) (middleware.Slot, bool) {
	switch s {
	case proto.MiddlewareSlot_MIDDLEWARE_SLOT_ON_REQUEST:
		return middleware.SlotOnRequest, true
	case proto.MiddlewareSlot_MIDDLEWARE_SLOT_ON_RESPONSE:
		return middleware.SlotOnResponse, true
	case proto.MiddlewareSlot_MIDDLEWARE_SLOT_TERMINAL:
		return middleware.SlotTerminal, true
	default:
		return 0, false
	}
}

// protoToMiddlewareFailMode maps the proto FailMode enum onto the
// internal middleware.FailMode, defaulting to FailOpen for any value
// other than FAIL_CLOSED.
func protoToMiddlewareFailMode(m proto.MiddlewareConfig_FailMode) middleware.FailMode {
	if m == proto.MiddlewareConfig_FAIL_CLOSED {
		return middleware.FailClosed
	}
	return middleware.FailOpen
}

// clampMiddlewareTimeout enforces the proxy-wide [MinTimeout, MaxTimeout]
// bounds and substitutes DefaultTimeout for zero inputs. A warn is logged
// only on an actual clamp, not when filling the default.
func clampMiddlewareTimeout(id string, d time.Duration) time.Duration {
	if d <= 0 {
		return middleware.DefaultTimeout
	}
	if d < middleware.MinTimeout {
		log.Debugf("middleware %s timeout %s clamped to %s", id, d, middleware.MinTimeout)
		return middleware.MinTimeout
	}
	if d > middleware.MaxTimeout {
		log.Debugf("middleware %s timeout %s clamped to %s", id, d, middleware.MaxTimeout)
		return middleware.MaxTimeout
	}
	return d
}
