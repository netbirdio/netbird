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
type denyResponse struct {
	Code       string            `json:"code"`
	Message    string            `json:"message,omitempty"`
	Details    map[string]string `json:"details,omitempty"`
	Middleware string            `json:"middleware,omitempty"`
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
