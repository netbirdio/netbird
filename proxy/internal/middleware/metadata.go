package middleware

import "regexp"

// keyRegex constrains metadata keys to the cross-domain shape
// described in keys.go. At least one dot, lowercase ASCII / digits /
// dot / underscore / hyphen only, length within MaxMetadataKeyBytes.
var keyRegex = regexp.MustCompile(`^[a-z][a-z0-9_-]*(\.[a-z0-9][a-z0-9_-]*)+$`)

// MetadataRejection describes a single rejected key/value so the
// dispatcher can emit per-reason counter increments.
type MetadataRejection struct {
	Key    string
	Reason string
}

// Rejection reasons reported by Accumulator.Emit.
const (
	MetadataReasonBadKey         = "bad_key"
	MetadataReasonNotAllowlisted = "not_allowlisted"
	MetadataReasonKeyTooLong     = "key_too_long"
	MetadataReasonValueTooLong   = "value_too_long"
	MetadataReasonMiddlewareCap  = "middleware_cap"
	MetadataReasonRequestCap     = "request_cap"
)

// Accumulator enforces per-middleware and per-request metadata caps.
// Not safe for concurrent use; callers hold one inside a single chain
// execution.
type Accumulator struct {
	perMiddlewareUsed map[string]int
	totalUsed         int
	maxPerRequest     int
}

// NewAccumulator returns an accumulator configured for the per-request
// total cap. A maxPerRequest of zero means use MaxRequestMetadataBytes.
func NewAccumulator(maxPerRequest int) *Accumulator {
	if maxPerRequest <= 0 {
		maxPerRequest = MaxRequestMetadataBytes
	}
	return &Accumulator{
		perMiddlewareUsed: make(map[string]int),
		maxPerRequest:     maxPerRequest,
	}
}

// Emit validates the candidate metadata against the middleware's
// allowlist and the global caps, redacts each accepted value, and
// returns the accepted entries plus any rejections for metric emission.
func (a *Accumulator) Emit(middlewareID string, allow []string, out []KV) ([]KV, []MetadataRejection) {
	if len(out) == 0 {
		return nil, nil
	}
	allowSet := make(map[string]struct{}, len(allow))
	for _, k := range allow {
		allowSet[k] = struct{}{}
	}

	accepted := make([]KV, 0, len(out))
	var rejected []MetadataRejection

	for _, kv := range out {
		if len(kv.Key) == 0 || len(kv.Key) > MaxMetadataKeyBytes {
			rejected = append(rejected, MetadataRejection{Key: kv.Key, Reason: MetadataReasonKeyTooLong})
			continue
		}
		if !keyRegex.MatchString(kv.Key) {
			rejected = append(rejected, MetadataRejection{Key: kv.Key, Reason: MetadataReasonBadKey})
			continue
		}
		if _, ok := allowSet[kv.Key]; !ok {
			rejected = append(rejected, MetadataRejection{Key: kv.Key, Reason: MetadataReasonNotAllowlisted})
			continue
		}
		if len(kv.Value) > MaxMetadataValueBytes {
			rejected = append(rejected, MetadataRejection{Key: kv.Key, Reason: MetadataReasonValueTooLong})
			continue
		}

		redacted := Scan(kv.Value)
		cost := len(kv.Key) + len(redacted)

		if a.perMiddlewareUsed[middlewareID]+cost > MaxMiddlewareMetadataBytes {
			rejected = append(rejected, MetadataRejection{Key: kv.Key, Reason: MetadataReasonMiddlewareCap})
			continue
		}
		if a.totalUsed+cost > a.maxPerRequest {
			rejected = append(rejected, MetadataRejection{Key: kv.Key, Reason: MetadataReasonRequestCap})
			continue
		}

		a.perMiddlewareUsed[middlewareID] += cost
		a.totalUsed += cost
		accepted = append(accepted, KV{Key: kv.Key, Value: redacted})
	}

	return accepted, rejected
}
