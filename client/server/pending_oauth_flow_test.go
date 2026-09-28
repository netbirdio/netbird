package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/auth"
)

type pkceFlowStub struct {
	clientID string
}

func (f *pkceFlowStub) RequestAuthInfo(context.Context) (auth.AuthFlowInfo, error) {
	return auth.AuthFlowInfo{}, nil
}

func (f *pkceFlowStub) WaitToken(context.Context, auth.AuthFlowInfo) (auth.TokenInfo, error) {
	return auth.TokenInfo{}, nil
}

func (f *pkceFlowStub) GetClientID(context.Context) string { return f.clientID }

func TestPendingOAuthFlowResponse(t *testing.T) {
	deviceFlow := func() auth.OAuthFlow { return &auth.DeviceAuthorizationFlow{} }
	pkceFlow := func() auth.OAuthFlow { return &pkceFlowStub{} }

	tests := []struct {
		name       string
		cached     auth.OAuthFlow
		requested  auth.OAuthFlow
		expiresIn  time.Duration
		wantReuse  bool
		wantCancel bool
	}{
		{
			name:      "no cached flow starts fresh",
			requested: deviceFlow(),
			expiresIn: 10 * time.Minute,
		},
		{
			name:      "device flow selected without the force flag is reused",
			cached:    deviceFlow(),
			requested: deviceFlow(),
			expiresIn: 10 * time.Minute,
			wantReuse: true,
		},
		{
			name:      "pkce flow is reused",
			cached:    pkceFlow(),
			requested: pkceFlow(),
			expiresIn: 10 * time.Minute,
			wantReuse: true,
		},
		{
			name:       "switching from pkce to device cancels the pending waiter",
			cached:     pkceFlow(),
			requested:  deviceFlow(),
			expiresIn:  10 * time.Minute,
			wantCancel: true,
		},
		{
			name:       "switching from device to pkce cancels the pending waiter",
			cached:     deviceFlow(),
			requested:  pkceFlow(),
			expiresIn:  10 * time.Minute,
			wantCancel: true,
		},
		{
			name:       "matching flow too close to expiry cancels the pending waiter",
			cached:     deviceFlow(),
			requested:  deviceFlow(),
			expiresIn:  30 * time.Second,
			wantCancel: true,
		},
		{
			name:      "mismatched client ID starts fresh without cancelling",
			cached:    &pkceFlowStub{clientID: "client-a"},
			requested: &pkceFlowStub{clientID: "client-b"},
			expiresIn: 10 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cancelled := false

			s := &Server{}
			s.oauthAuthFlow.flow = tt.cached
			s.oauthAuthFlow.expiresAt = time.Now().Add(tt.expiresIn)
			s.oauthAuthFlow.info.UserCode = "pending-code"
			s.oauthAuthFlow.waitCancel = func() { cancelled = true }

			resp := s.pendingOAuthFlowResponse(context.Background(), tt.requested)

			if tt.wantReuse {
				require.NotNil(t, resp, "expected the pending flow to be reused")
				require.True(t, resp.NeedsSSOLogin, "reused flow must still require SSO login")
				require.Equal(t, "pending-code", resp.UserCode, "reused flow must expose the pending user code")
			} else {
				require.Nil(t, resp, "expected the caller to start a fresh flow")
			}

			require.Equal(t, tt.wantCancel, cancelled, "unexpected waitCancel behaviour")
		})
	}
}

func TestOAuthFlowCleanupSkipsReplacedFlow(t *testing.T) {
	newServer := func(flow auth.OAuthFlow, expiresAt time.Time) *Server {
		s := &Server{}
		s.oauthAuthFlow.flow = flow
		s.oauthAuthFlow.expiresAt = expiresAt
		return s
	}

	current := &auth.DeviceAuthorizationFlow{}
	stale := &pkceFlowStub{}
	expiry := time.Now().Add(10 * time.Minute)

	t.Run("stale waiter does not expire the replacement", func(t *testing.T) {
		s := newServer(current, expiry)

		s.expireOAuthFlow(stale)

		require.Equal(t, expiry, s.oauthAuthFlow.expiresAt, "replacement expiry must survive a stale waiter")
	})

	t.Run("stale waiter does not clear the replacement", func(t *testing.T) {
		s := newServer(current, expiry)

		s.clearOAuthFlow(stale)

		require.Same(t, current, s.oauthAuthFlow.flow, "replacement flow must survive a stale waiter")
		require.Equal(t, expiry, s.oauthAuthFlow.expiresAt, "replacement expiry must survive a stale waiter")
	})

	t.Run("waiter expires the flow it was started for", func(t *testing.T) {
		s := newServer(current, expiry)

		s.expireOAuthFlow(current)

		require.WithinDuration(t, time.Now(), s.oauthAuthFlow.expiresAt, time.Minute,
			"own flow must be marked spent")
	})

	t.Run("waiter clears the flow it was started for", func(t *testing.T) {
		s := newServer(current, expiry)

		s.clearOAuthFlow(current)

		require.Nil(t, s.oauthAuthFlow.flow, "own flow must be dropped")
	})
}
