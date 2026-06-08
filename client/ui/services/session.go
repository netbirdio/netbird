//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"

	"github.com/netbirdio/netbird/client/ui/authsession"
)

// Re-exports so frontend bindings stay on services.ExtendStart* /
// services.ExtendWait* / services.ExtendResult without each call site
// importing authsession.
type (
	ExtendStartParams = authsession.ExtendStartParams
	ExtendStartResult = authsession.ExtendStartResult
	ExtendWaitParams  = authsession.ExtendWaitParams
	ExtendResult      = authsession.ExtendResult
)

// Session is the Wails-bound wrapper around authsession.Session. It only
// re-exposes the subset the React frontend actually calls
// (SessionExpirationDialog.tsx: RequestExtend + WaitExtend). The tray
// uses authsession.Session directly, so methods that only the tray needs
// (DismissWarning) are deliberately absent here — keeping the generated
// TS surface minimal.
type Session struct {
	inner *authsession.Session
}

// NewSession returns the Wails-bound wrapper. The caller owns the inner
// authsession.Session and may use it directly (e.g. the tray).
func NewSession(inner *authsession.Session) *Session {
	return &Session{inner: inner}
}

// RequestExtend starts the SSO session-extension flow on the daemon and
// returns the verification URI for the UI to open.
func (s *Session) RequestExtend(ctx context.Context, p ExtendStartParams) (ExtendStartResult, error) {
	return s.inner.RequestExtend(ctx, p)
}

// WaitExtend blocks until the user completes the SSO flow started by
// RequestExtend, then returns the new session deadline (or nil when the
// management server reports the peer ineligible).
func (s *Session) WaitExtend(ctx context.Context, p ExtendWaitParams) (ExtendResult, error) {
	return s.inner.WaitExtend(ctx, p)
}
