package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/auth"
	"github.com/netbirdio/netbird/client/proto"
)

type stubOAuthFlow struct {
	token auth.TokenInfo
}

func (f *stubOAuthFlow) RequestAuthInfo(context.Context) (auth.AuthFlowInfo, error) {
	return auth.AuthFlowInfo{}, nil
}

func (f *stubOAuthFlow) WaitToken(context.Context, auth.AuthFlowInfo) (auth.TokenInfo, error) {
	return f.token, nil
}

func (f *stubOAuthFlow) GetClientID(context.Context) string {
	return "stub-client"
}

func TestWaitSSOLogin_WrongAccountArmsPromptAndFails(t *testing.T) {
	s := newSSOTestServer(t, "user@example.com", false, "other@example.com")
	attempts := 0
	s.loginAttemptFn = func(context.Context, string, string) (internal.StatusType, error) {
		attempts++
		return "", nil
	}

	resp, err := s.WaitSSOLogin(context.Background(), &proto.WaitSSOLoginRequest{UserCode: "code"})
	require.Error(t, err)
	require.Nil(t, resp)
	require.Equal(t, 0, attempts, "the wrong account's token reached the management login")
	require.True(t, s.forceAccountPrompt, "the next login was not armed to ask for the account")
	require.Nil(t, s.oauthAuthFlow.flow, "the mismatched flow stayed cached for reuse")

	status, stateErr := internal.CtxGetState(s.rootCtx).Status()
	require.NoError(t, stateErr)
	require.Equal(t, internal.StatusNeedsLogin, status, "the mismatch must stay retryable")
}

func TestWaitSSOLogin_WrongAccountAfterPromptProceeds(t *testing.T) {
	s := newSSOTestServer(t, "user@example.com", true, "other@example.com")
	attempts := 0
	s.loginAttemptFn = func(context.Context, string, string) (internal.StatusType, error) {
		attempts++
		return "", nil
	}

	resp, err := s.WaitSSOLogin(context.Background(), &proto.WaitSSOLoginRequest{UserCode: "code"})
	require.NoError(t, err, "a prompted round must not error again on a mismatch")
	require.NotNil(t, resp)
	require.Equal(t, "other@example.com", resp.Email)
	require.Equal(t, 1, attempts)
	require.False(t, s.forceAccountPrompt)
}

func TestWaitSSOLogin_MatchingAccountProceeds(t *testing.T) {
	s := newSSOTestServer(t, "user@example.com", false, "User@Example.com")
	attempts := 0
	s.loginAttemptFn = func(context.Context, string, string) (internal.StatusType, error) {
		attempts++
		return "", nil
	}

	resp, err := s.WaitSSOLogin(context.Background(), &proto.WaitSSOLoginRequest{UserCode: "code"})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, 1, attempts)
	require.False(t, s.forceAccountPrompt)
}

func TestWaitSSOLogin_NoHintIsNotJudged(t *testing.T) {
	s := newSSOTestServer(t, "", false, "whoever@example.com")
	attempts := 0
	s.loginAttemptFn = func(context.Context, string, string) (internal.StatusType, error) {
		attempts++
		return "", nil
	}

	_, err := s.WaitSSOLogin(context.Background(), &proto.WaitSSOLoginRequest{UserCode: "code"})
	require.NoError(t, err)
	require.Equal(t, 1, attempts)
	require.False(t, s.forceAccountPrompt)
}

func TestSwitchProfile_DropsAccountPromptAndPendingFlow(t *testing.T) {
	s, ctx, _, _, _ := setupServerWithProfile(t)
	s.forceAccountPrompt = true
	cancelled := false
	s.oauthAuthFlow = oauthAuthFlow{
		flow:       &stubOAuthFlow{},
		hint:       "user@example.com",
		waitCancel: func() { cancelled = true },
	}

	_, err := s.SwitchProfile(ctx, nil)
	require.NoError(t, err)
	require.False(t, s.forceAccountPrompt, "the prompt flag leaked across a profile switch")
	require.Nil(t, s.oauthAuthFlow.flow, "the previous profile's flow leaked across a profile switch")
	require.Empty(t, s.oauthAuthFlow.hint)
	require.True(t, cancelled, "the pending wait was not cancelled")
}

func newSSOTestServer(t *testing.T, hint string, accountPrompted bool, tokenEmail string) *Server {
	t.Helper()
	s := New(internal.CtxInitState(context.Background()), "console", "", false, false, false, false)
	s.oauthAuthFlow = oauthAuthFlow{
		flow:            &stubOAuthFlow{token: auth.TokenInfo{Email: tokenEmail, EmailClaim: tokenEmail}},
		info:            auth.AuthFlowInfo{UserCode: "code"},
		expiresAt:       time.Now().Add(time.Minute),
		hint:            hint,
		accountPrompted: accountPrompted,
	}
	return s
}
