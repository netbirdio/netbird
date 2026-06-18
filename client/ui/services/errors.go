//go:build !android && !ios && !freebsd && !js

package services

import (
	"encoding/json"
	"strings"

	gcodes "google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/ui/i18n"
	"github.com/netbirdio/netbird/client/ui/preferences"
)

// ErrorTranslator localises daemon errors; runtime impl is *i18n.Bundle.
type ErrorTranslator interface {
	Translate(lang i18n.LanguageCode, key string, args ...string) string
}

// LanguagePreference reports the current UI language; runtime impl is *preferences.Store.
type LanguagePreference interface {
	Get() preferences.UIPreferences
}

// ClientError is a structured error returned to the frontend. The frontend
// translates Code via i18n; Short is an English fallback; Long carries the
// unwrapped daemon message.
type ClientError struct {
	Code  string `json:"code"`
	Short string `json:"short"`
	Long  string `json:"long"`
}

// Error returns the short message for plain Go callers.
func (e *ClientError) Error() string {
	if e == nil {
		return ""
	}
	return e.Short
}

// MarshalJSON emits the struct so the Wails binding sends an object, not the
// default "error: ..." string.
func (e *ClientError) MarshalJSON() ([]byte, error) {
	if e == nil {
		return []byte("null"), nil
	}
	type alias ClientError
	return json.Marshal((*alias)(e))
}

// errorClassifier maps gRPC errors to a localised ClientError. Shared by the
// daemon-facing services so the frontend gets a clean short message instead of
// the wrapped gRPC chain.
type errorClassifier struct {
	translator ErrorTranslator
	prefs      LanguagePreference
}

// classify maps a gRPC error to a ClientError by matching known substrings to a
// stable code. A missing locale entry surfaces as a visible "error.<code>"
// string — a deliberate fail-loud signal to update the bundle.
func (c errorClassifier) classify(err error) *ClientError {
	if err == nil {
		return nil
	}

	msg := err.Error()
	grpcCode := gcodes.Unknown
	if st, ok := gstatus.FromError(err); ok {
		msg = st.Message()
		grpcCode = st.Code()
	}
	lower := strings.ToLower(msg)

	code := "unknown"
	switch {
	case strings.Contains(lower, "token used before issued"),
		strings.Contains(lower, "token is not valid yet"):
		code = "jwt_clock_skew"
	case strings.Contains(lower, "token is expired"),
		strings.Contains(lower, "token has expired"):
		code = "jwt_expired"
	case strings.Contains(lower, "token signature is invalid"):
		code = "jwt_signature_invalid"
	case strings.Contains(lower, "peer login has expired"):
		code = "session_expired"
	case strings.Contains(lower, "invalid setup-key"),
		strings.Contains(lower, "invalid setup key"):
		code = "invalid_setup_key"
	case strings.Contains(lower, "permission denied"):
		code = "permission_denied"
	case strings.Contains(lower, "no connection could be made"),
		strings.Contains(lower, "connection refused"),
		strings.Contains(lower, "context deadline exceeded"):
		code = "daemon_unreachable"
	}

	// Fall back to the gRPC status code when the message didn't match a known
	// substring — the daemon now forwards the innermost code with a clean desc
	// that no longer contains the English marker text.
	if code == "unknown" {
		switch grpcCode {
		case gcodes.PermissionDenied:
			code = "permission_denied"
		case gcodes.Unavailable, gcodes.DeadlineExceeded:
			code = "daemon_unreachable"
		}
	}

	return &ClientError{
		Code:  code,
		Short: c.translateShort(code),
		Long:  msg,
	}
}

// translateShort resolves the localised short message for code, returning the
// bare "error.<code>" key when no translation is available so the gap stays visible.
func (c errorClassifier) translateShort(code string) string {
	key := "error." + code
	if c.translator == nil {
		return key
	}
	lang := i18n.DefaultLanguage
	if c.prefs != nil {
		if pref := c.prefs.Get().Language; pref != "" {
			lang = pref
		}
	}
	return c.translator.Translate(lang, key)
}
