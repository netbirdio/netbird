package server

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/proto"
)

// A login that never reached Management is not a decision about the peer's
// credentials, so it must come back as a retryable error rather than an SSO
// prompt: the user cannot finish a browser login while Management is down, and
// the CLI's own backoff resolves the outage on its own once the daemon reports
// the failure. Reproduces `netbird down; netbird up` printing a device-code URL
// because Management happened to be restarting when the daemon dialed it.
func TestLogin_ManagementUnreachableIsReturnedInsteadOfDemandingSSO(t *testing.T) {
	s, _, _, username, _ := setupServerWithProfile(t)
	s.rootCtx = internal.CtxInitState(context.Background())

	unreachable := errors.New("create connection: dial context: context deadline exceeded")
	attempts := 0
	s.loginAttemptFn = func(context.Context, string, string) (internal.StatusType, error) {
		attempts++
		return internal.StatusLoginFailed, unreachable
	}

	resp, err := s.Login(userCtx(), &proto.LoginRequest{Username: &username})
	require.Error(t, err)
	require.ErrorIs(t, err, unreachable, "the transport failure was replaced by something else")
	require.Nil(t, resp, "a failed login must not answer with a login response")
	require.Equal(t, 1, attempts)
	require.Nil(t, s.oauthAuthFlow.flow, "the daemon started an SSO flow for a peer whose login was never decided")

	status, err := internal.CtxGetState(s.rootCtx).Status()
	require.NoError(t, err)
	require.Equal(t, internal.StatusLoginFailed, status,
		"a peer that could not reach Management is not waiting on a login")
}

// The counterpart: Management refusing the peer's credentials is a decision, and
// the SSO flow still has to start for it. The profile carries an unusable
// private key so the flow setup fails immediately instead of dialing, which is
// enough to show the branch was entered — the refusal itself is never what comes
// back out.
func TestLogin_AuthRefusalStartsSSOFlow(t *testing.T) {
	s, _, _, username, cfgPath := setupServerWithProfile(t)
	s.rootCtx = internal.CtxInitState(context.Background())
	breakProfilePrivateKey(t, cfgPath)

	refused := gstatus.Error(codes.PermissionDenied, "peer is not registered")
	s.loginAttemptFn = func(context.Context, string, string) (internal.StatusType, error) {
		return internal.StatusNeedsLogin, refused
	}

	_, err := s.Login(userCtx(), &proto.LoginRequest{Username: &username})
	require.Error(t, err)
	require.NotErrorIs(t, err, refused,
		"the refusal was handed back to the caller instead of starting the SSO flow")

	status, stateErr := internal.CtxGetState(s.rootCtx).Status()
	require.NoError(t, stateErr)
	require.Equal(t, internal.StatusLoginFailed, status,
		"the SSO flow setup was never reached with the broken key")
}

// breakProfilePrivateKey replaces the profile's private key with an unparseable
// one, which makes any attempt to build a Management client fail on the spot.
func breakProfilePrivateKey(t *testing.T, cfgPath string) {
	t.Helper()

	raw, err := os.ReadFile(cfgPath)
	require.NoError(t, err)

	var cfg map[string]any
	require.NoError(t, json.Unmarshal(raw, &cfg))
	cfg["PrivateKey"] = "not-a-key"

	patched, err := json.Marshal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(cfgPath, patched, 0o600))
}
