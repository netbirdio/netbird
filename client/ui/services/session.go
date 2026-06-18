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
	inner      *authsession.Session
	classifier errorClassifier
}

// NewSession wraps inner; the caller retains ownership and may use it directly.
// translator or prefs may be nil, in which case errors fall back to the bare code key.
func NewSession(inner *authsession.Session, translator ErrorTranslator, prefs LanguagePreference) *Session {
	return &Session{inner: inner, classifier: errorClassifier{translator: translator, prefs: prefs}}
}

// RequestExtend starts the SSO session-extension flow; the result carries the verification URI to open.
func (s *Session) RequestExtend(ctx context.Context, p ExtendStartParams) (ExtendStartResult, error) {
	res, err := s.inner.RequestExtend(ctx, p)
	if err != nil {
		return ExtendStartResult{}, s.classifier.classify(err)
	}
	return res, nil
}

// WaitExtend blocks until the RequestExtend flow completes; the deadline is nil when the peer is ineligible.
func (s *Session) WaitExtend(ctx context.Context, p ExtendWaitParams) (ExtendResult, error) {
	res, err := s.inner.WaitExtend(ctx, p)
	if err != nil {
		return ExtendResult{}, s.classifier.classify(err)
	}
	return res, nil
}
