package server

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/auth"
	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
)

type stubOAuthFlow struct {
	token  auth.TokenInfo
	onWait func()
}

func (f *stubOAuthFlow) RequestAuthInfo(context.Context) (auth.AuthFlowInfo, error) {
	return auth.AuthFlowInfo{}, nil
}

func (f *stubOAuthFlow) WaitToken(context.Context, auth.AuthFlowInfo) (auth.TokenInfo, error) {
	if f.onWait != nil {
		f.onWait()
	}
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

	resp, err := s.WaitSSOLogin(callerCtx(t), &proto.WaitSSOLoginRequest{UserCode: "code"})
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

	resp, err := s.WaitSSOLogin(callerCtx(t), &proto.WaitSSOLoginRequest{UserCode: "code"})
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

	resp, err := s.WaitSSOLogin(callerCtx(t), &proto.WaitSSOLoginRequest{UserCode: "code"})
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

	_, err := s.WaitSSOLogin(callerCtx(t), &proto.WaitSSOLoginRequest{UserCode: "code"})
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

	extendCancelled := false
	s.extendAuthSessionFlow.Set(&stubOAuthFlow{}, auth.AuthFlowInfo{DeviceCode: "device"})
	s.extendAuthSessionFlow.SetWaitCancel(func() { extendCancelled = true })

	_, err := s.SwitchProfile(ctx, nil)
	require.NoError(t, err)
	require.False(t, s.forceAccountPrompt, "the prompt flag leaked across a profile switch")
	require.Nil(t, s.oauthAuthFlow.flow, "the previous profile's flow leaked across a profile switch")
	require.Empty(t, s.oauthAuthFlow.hint)
	require.True(t, cancelled, "the pending wait was not cancelled")

	require.True(t, extendCancelled, "the pending extend wait was not cancelled")
	_, _, pending := s.extendAuthSessionFlow.Get()
	require.False(t, pending, "the previous profile's extend flow leaked across a profile switch")
}

func TestLogin_ProfileSwitchDropsAccountPromptAndPendingFlow(t *testing.T) {
	s, _, _, username, cfgPath := setupServerWithProfile(t)
	s.rootCtx = internal.CtxInitState(context.Background())
	s.isLoginRequiredFn = func(context.Context) (bool, error) {
		return true, nil
	}

	other := "other-profile"
	otherPath := filepath.Join(filepath.Dir(cfgPath), other+".json")
	_, err := profilemanager.UpdateOrCreateConfig(profilemanager.ConfigInput{
		ConfigPath:    otherPath,
		ManagementURL: "https://api.netbird.io:443",
	})
	require.NoError(t, err)
	breakProfilePrivateKey(t, otherPath)

	s.forceAccountPrompt = true
	cancelled := false
	s.oauthAuthFlow = oauthAuthFlow{
		flow:       &stubOAuthFlow{},
		hint:       "user@example.com",
		waitCancel: func() { cancelled = true },
	}

	extendCancelled := false
	s.extendAuthSessionFlow.Set(&stubOAuthFlow{}, auth.AuthFlowInfo{DeviceCode: "device"})
	s.extendAuthSessionFlow.SetWaitCancel(func() { extendCancelled = true })

	_, err = s.Login(userCtx(), &proto.LoginRequest{ProfileName: &other, Username: &username})
	require.Error(t, err, "the broken key must stop the login before a flow is built")

	active, err := s.profileManager.GetActiveProfileState()
	require.NoError(t, err)
	require.Equal(t, profilemanager.ID(other), active.ID, "the login did not switch the profile")

	require.False(t, s.forceAccountPrompt, "the prompt flag leaked across a login-driven profile switch")
	require.Nil(t, s.oauthAuthFlow.flow, "the previous profile's flow leaked across a login-driven profile switch")
	require.Empty(t, s.oauthAuthFlow.hint)
	require.True(t, cancelled, "the pending wait was not cancelled")

	require.True(t, extendCancelled, "the pending extend wait was not cancelled")
	_, _, pending := s.extendAuthSessionFlow.Get()
	require.False(t, pending, "the previous profile's extend flow leaked across a login-driven profile switch")
}

func TestLogin_SameProfileKeepsPendingFlow(t *testing.T) {
	s, _, profName, username, cfgPath := setupServerWithProfile(t)
	s.rootCtx = internal.CtxInitState(context.Background())
	s.isLoginRequiredFn = func(context.Context) (bool, error) {
		return true, nil
	}
	breakProfilePrivateKey(t, cfgPath)

	cancelled := false
	flow := &stubOAuthFlow{}
	s.oauthAuthFlow = oauthAuthFlow{
		flow:       flow,
		hint:       "user@example.com",
		waitCancel: func() { cancelled = true },
	}

	_, err := s.Login(userCtx(), &proto.LoginRequest{ProfileName: &profName, Username: &username})
	require.Error(t, err, "the broken key must stop the login before a flow is built")

	require.Equal(t, flow, s.oauthAuthFlow.flow, "a login on the same profile dropped the flow a second client could join")
	require.Equal(t, "user@example.com", s.oauthAuthFlow.hint)
	require.False(t, cancelled, "a login on the same profile cancelled the pending wait")
}

func TestWaitSSOLogin_JudgesTheFlowThatProducedTheToken(t *testing.T) {
	s := newSSOTestServer(t, "user@example.com", false, "user@example.com")
	attempts := 0
	s.loginAttemptFn = func(context.Context, string, string) (internal.StatusType, error) {
		attempts++
		return "", nil
	}

	flow := s.oauthAuthFlow.flow.(*stubOAuthFlow)
	flow.onWait = func() {
		s.mutex.Lock()
		defer s.mutex.Unlock()
		s.oauthAuthFlow.hint = "someone-else@example.com"
	}

	resp, err := s.WaitSSOLogin(callerCtx(t), &proto.WaitSSOLoginRequest{UserCode: "code"})
	require.NoError(t, err, "a flow replaced mid-wait must not decide this wait's verdict")
	require.NotNil(t, resp)
	require.Equal(t, 1, attempts)
	require.False(t, s.forceAccountPrompt, "the prompt was armed off another flow's hint")
}

func TestReuseOAuthFlow_ForcedPromptRefusesTheCachedFlow(t *testing.T) {
	s := New(internal.CtxInitState(context.Background()), "console", "", false, false, false, false)
	cancelled := false
	s.oauthAuthFlow = oauthAuthFlow{
		flow:       &stubOAuthFlow{},
		info:       auth.AuthFlowInfo{UserCode: "code"},
		expiresAt:  time.Now().Add(time.Hour),
		waitCancel: func() { cancelled = true },
	}

	state := internal.CtxGetState(s.rootCtx)
	resp := s.reuseOAuthFlow(context.Background(), &stubOAuthFlow{}, state, true)
	require.Nil(t, resp, "a forced account prompt reused the flow that skipped it")
	require.True(t, cancelled, "the predecessor wait was orphaned")

	resp = s.reuseOAuthFlow(context.Background(), &stubOAuthFlow{}, state, false)
	require.NotNil(t, resp, "an unforced login stopped reusing a live flow")
	require.Equal(t, "code", resp.UserCode)
}

func TestReplaceOAuthFlow_CancelsTheDisplacedWait(t *testing.T) {
	s := New(internal.CtxInitState(context.Background()), "console", "", false, false, false, false)
	cancelled := false
	s.oauthAuthFlow = oauthAuthFlow{
		flow:            &stubOAuthFlow{},
		info:            auth.AuthFlowInfo{UserCode: "code"},
		expiresAt:       time.Now().Add(time.Hour),
		hint:            "user@example.com",
		accountPrompted: true,
		waitCancel:      func() { cancelled = true },
	}

	next := &stubOAuthFlow{}
	s.replaceOAuthFlow(oauthAuthFlow{flow: next, info: auth.AuthFlowInfo{UserCode: "next"}})

	require.True(t, cancelled, "the displaced wait was left without an owner")
	require.Equal(t, next, s.oauthAuthFlow.flow)
	require.Equal(t, "next", s.oauthAuthFlow.info.UserCode)
	require.Empty(t, s.oauthAuthFlow.hint, "the previous flow's hint survived the replacement")
	require.False(t, s.oauthAuthFlow.accountPrompted)
	require.Nil(t, s.oauthAuthFlow.waitCancel, "the consumed cancel stayed on the record")
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

// callerCtx is the gRPC caller's context. WaitSSOLogin parks a goroutine on it
// for the whole browser leg, so a test that never cancels leaks one.
func callerCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return ctx
}
