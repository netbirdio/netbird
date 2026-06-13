//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"

	"github.com/netbirdio/netbird/client/ui/authsession"
)

// Re-exports so generated bindings reference services.* without importing authsession.
type (
	ExtendStartParams = authsession.ExtendStartParams
	ExtendStartResult = authsession.ExtendStartResult
	ExtendWaitParams  = authsession.ExtendWaitParams
	ExtendResult      = authsession.ExtendResult
)

// Session wraps authsession.Session, exposing only the subset the React frontend
// calls; the tray uses authsession.Session directly, keeping the generated TS surface minimal.
type Session struct {
	inner *authsession.Session
}

// NewSession wraps inner; the caller retains ownership and may use it directly.
func NewSession(inner *authsession.Session) *Session {
	return &Session{inner: inner}
}

// RequestExtend starts the SSO session-extension flow; the result carries the verification URI to open.
func (s *Session) RequestExtend(ctx context.Context, p ExtendStartParams) (ExtendStartResult, error) {
	return s.inner.RequestExtend(ctx, p)
}

// WaitExtend blocks until the RequestExtend flow completes; the deadline is nil when the peer is ineligible.
func (s *Session) WaitExtend(ctx context.Context, p ExtendWaitParams) (ExtendResult, error) {
	return s.inner.WaitExtend(ctx, p)
}
