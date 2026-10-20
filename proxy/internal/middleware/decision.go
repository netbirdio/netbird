package middleware

import (
	"encoding/json"
	"net/http"
	"regexp"
)

var codeRegex = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)

// denyResponse is the on-wire shape rendered by RenderDenyResponse.
// Keeping this as a typed struct ensures we never leak
// middleware-supplied bytes outside known fields.
//
// Type and Error mirror the denial in the vendor's own error shape when
// the request reached a known LLM surface. LLM clients only parse their
// provider's envelope, so without the mirror a budget stop reaches the
// user as an unexplained API error. The NetBird fields stay where they
// were, so the body is a superset and existing consumers are unaffected.
type denyResponse struct {
	Code       string            `json:"code"`
	Message    string            `json:"message,omitempty"`
	Details    map[string]string `json:"details,omitempty"`
	Middleware string            `json:"middleware,omitempty"`
	Type       string            `json:"type,omitempty"`
	Error      *providerError    `json:"error,omitempty"`
}

// providerError is the nested error object both vendor envelopes carry.
type providerError struct {
	Type    string `json:"type"`
	Message string `json:"message,omitempty"`
	Code    string `json:"code,omitempty"`
}

// Vendor error types keyed by HTTP status, per each provider's published
// error reference.
const (
	anthropicErrInvalidRequest = "invalid_request_error"
	anthropicErrPermission     = "permission_error"
	anthropicErrRateLimit      = "rate_limit_error"
	anthropicErrAPI            = "api_error"
	openAIErrInvalidRequest    = "invalid_request_error"
	openAIErrRateLimit         = "rate_limit_error"
)

// providerEnvelope returns the vendor-shaped mirror for a denial on the
// given surface, or nil when the surface has no envelope we can speak.
// message is the already-redacted public message.
func providerEnvelope(surface, code, message string, status int) (string, *providerError) {
	switch surface {
	case "anthropic":
		return "error", &providerError{
			Type:    anthropicErrorType(status),
			Message: message,
		}
	case "openai":
		return "", &providerError{
			Type:    openAIErrorType(status),
			Message: message,
			Code:    code,
		}
	default:
		return "", nil
	}
}

func anthropicErrorType(status int) string {
	switch status {
	case http.StatusForbidden:
		return anthropicErrPermission
	case http.StatusTooManyRequests:
		return anthropicErrRateLimit
	case http.StatusBadRequest:
		return anthropicErrInvalidRequest
	default:
		return anthropicErrAPI
	}
}

func openAIErrorType(status int) string {
	if status == http.StatusTooManyRequests {
		return openAIErrRateLimit
	}
	return openAIErrInvalidRequest
}

// RenderDenyResponse writes a structured JSON deny body. Status is
// clamped to [400, 499] excluding 401 (to avoid conflicts with the
// proxy's auth flow). All middleware-supplied strings are redacted and
// truncated. On any validation failure the function writes a generic
// 403.
func RenderDenyResponse(w http.ResponseWriter, middlewareID string, reason *DenyReason, defaultStatus int) {
	status := clampDenyStatus(defaultStatus)

	if reason == nil || !codeRegex.MatchString(reason.Code) {
		writeGenericDeny(w, middlewareID, status)
		return
	}

	resp := denyResponse{
		Code:       reason.Code,
		Message:    truncate(Scan(reason.Message), 256),
		Middleware: truncate(Scan(middlewareID), 64),
	}
	resp.Type, resp.Error = providerEnvelope(reason.Surface, resp.Code, resp.Message, status)
	if n := len(reason.Details); n > 0 {
		resp.Details = make(map[string]string, min(n, 8))
		for k, v := range reason.Details {
			if len(resp.Details) >= 8 {
				break
			}
			safeKey := truncate(Scan(k), 64)
			if safeKey == "" {
				continue
			}
			resp.Details[safeKey] = truncate(Scan(v), 256)
		}
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		return
	}
}

func writeGenericDeny(w http.ResponseWriter, middlewareID string, status int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(denyResponse{Code: "middleware.error", Middleware: truncate(Scan(middlewareID), 64)})
}

func clampDenyStatus(s int) int {
	if s < 400 || s >= 500 {
		return http.StatusForbidden
	}
	if s == http.StatusUnauthorized {
		return http.StatusForbidden
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
