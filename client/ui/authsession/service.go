//go:build !android && !ios && !freebsd && !js

package authsession

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/proto"
)

type ExtendStartParams struct {
	// Hint is the OIDC login_hint, typically the user's email.
	Hint string `json:"hint"`
}

type ExtendStartResult struct {
	VerificationURI         string `json:"verificationUri"`
	VerificationURIComplete string `json:"verificationUriComplete"`
	UserCode                string `json:"userCode"`
	DeviceCode              string `json:"deviceCode"`
	ExpiresIn               int64  `json:"expiresIn"`
}

type ExtendWaitParams struct {
	DeviceCode string `json:"deviceCode"`
	UserCode   string `json:"userCode"`
}

// ExtendResult: ExpiresAt is nil when the peer is ineligible for extension.
// Preempted means a newer WaitExtend took over the IdP poll — a no-op, not a failure.
type ExtendResult struct {
	ExpiresAt *time.Time `json:"sessionExpiresAt,omitempty"`
	Preempted bool       `json:"preempted,omitempty"`
}

// DaemonConn duplicates services.DaemonConn to avoid an import cycle.
type DaemonConn interface {
	Client() (proto.DaemonServiceClient, error)
}

// Session bundles the session-auth daemon RPCs the UI drives.
type Session struct {
	conn DaemonConn
}

func NewSession(conn DaemonConn) *Session {
	return &Session{conn: conn}
}

// RequestExtend starts the SSO session-extension flow on the daemon.
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

// WaitExtend blocks until the user completes the SSO flow started by RequestExtend.
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

// DismissWarning suppresses the daemon's T-FinalWarningLead fallback dialog for
// the current deadline. Best-effort: a stale call is silently swallowed daemon-side.
func (s *Session) DismissWarning(ctx context.Context) error {
	cli, err := s.conn.Client()
	if err != nil {
		return err
	}
	_, err = cli.DismissSessionWarning(ctx, &proto.DismissSessionWarningRequest{})
	return err
}
