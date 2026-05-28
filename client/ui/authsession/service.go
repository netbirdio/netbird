//go:build !android && !ios && !freebsd && !js

package authsession

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/proto"
)

// ExtendStartParams optionally pre-fills the IdP login form.
type ExtendStartParams struct {
	// Hint is the OIDC login_hint, typically the user's email.
	Hint string `json:"hint"`
}

// ExtendStartResult tells the UI what to open and how to match the
// follow-up Wait call to the daemon's pending flow.
type ExtendStartResult struct {
	VerificationURI         string `json:"verificationUri"`
	VerificationURIComplete string `json:"verificationUriComplete"`
	UserCode                string `json:"userCode"`
	DeviceCode              string `json:"deviceCode"`
	ExpiresIn               int64  `json:"expiresIn"`
}

// ExtendWaitParams identifies the pending flow by the device/user code
// the UI received from RequestExtend.
type ExtendWaitParams struct {
	DeviceCode string `json:"deviceCode"`
	UserCode   string `json:"userCode"`
}

// ExtendResult carries the refreshed deadline. ExpiresAt is nil when the
// management server reported the peer is not eligible for session
// extension. Preempted is true when a newer WaitExtend (e.g. started from
// another UI surface for the same deadline) took over the IdP poll —
// callers should treat the call as a no-op rather than a failure.
type ExtendResult struct {
	ExpiresAt *time.Time `json:"sessionExpiresAt,omitempty"`
	Preempted bool       `json:"preempted,omitempty"`
}

// DaemonConn yields a lazy daemon gRPC client. Mirrors services.DaemonConn
// in the Wails services package; duplicated here so the Session can be
// owned by authsession without an import cycle.
type DaemonConn interface {
	Client() (proto.DaemonServiceClient, error)
}

// Session bundles the session-auth daemon RPCs the UI drives — the
// interactive extend flow (RequestExtend + WaitExtend) and the Dismiss
// hand-off. The tray uses it directly; the Wails-bound wrapper in
// client/ui/services exposes only the subset the React frontend needs.
type Session struct {
	conn DaemonConn
}

// NewSession returns a Session backed by the shared daemon connection.
func NewSession(conn DaemonConn) *Session {
	return &Session{conn: conn}
}

// RequestExtend starts the SSO session-extension flow on the daemon and
// returns the verification URI for the UI to open.
func (s *Session) RequestExtend(ctx context.Context, p ExtendStartParams) (ExtendStartResult, error) {
	cli, err := s.conn.Client()
	if err != nil {
		return ExtendStartResult{}, err
	}

	req := &proto.RequestExtendAuthSessionRequest{}
	if p.Hint != "" {
		h := p.Hint
		req.Hint = &h
	}

	resp, err := cli.RequestExtendAuthSession(ctx, req)
	if err != nil {
		return ExtendStartResult{}, err
	}

	return ExtendStartResult{
		VerificationURI:         resp.GetVerificationURI(),
		VerificationURIComplete: resp.GetVerificationURIComplete(),
		UserCode:                resp.GetUserCode(),
		DeviceCode:              resp.GetDeviceCode(),
		ExpiresIn:               resp.GetExpiresIn(),
	}, nil
}

// WaitExtend blocks until the user completes the SSO flow started by
// RequestExtend, then returns the new session deadline (or nil when the
// management server reports the peer ineligible).
func (s *Session) WaitExtend(ctx context.Context, p ExtendWaitParams) (ExtendResult, error) {
	cli, err := s.conn.Client()
	if err != nil {
		return ExtendResult{}, err
	}

	resp, err := cli.WaitExtendAuthSession(ctx, &proto.WaitExtendAuthSessionRequest{
		DeviceCode: p.DeviceCode,
		UserCode:   p.UserCode,
	})
	if err != nil {
		if st, ok := gstatus.FromError(err); ok && st.Code() == codes.Canceled {
			return ExtendResult{Preempted: true}, nil
		}
		return ExtendResult{}, err
	}

	out := ExtendResult{}
	if ts := resp.GetSessionExpiresAt(); ts.IsValid() && !ts.AsTime().IsZero() {
		t := ts.AsTime().UTC()
		out.ExpiresAt = &t
	}
	return out, nil
}

// DismissWarning records the user's "Dismiss" click on the T-WarningLead
// notification so the daemon suppresses the T-FinalWarningLead fallback
// dialog for the current deadline. Best-effort: the daemon never reports
// a "deadline not found" error — a stale or no-op call is silently swallowed.
func (s *Session) DismissWarning(ctx context.Context) error {
	cli, err := s.conn.Client()
	if err != nil {
		return err
	}
	_, err = cli.DismissSessionWarning(ctx, &proto.DismissSessionWarningRequest{})
	return err
}
