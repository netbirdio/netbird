package auth

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	mgm "github.com/netbirdio/netbird/shared/management/client"
)

// stubFlow is a minimal OAuthFlow returned by the fake initializers below. requestErr, when set,
// is what its RequestAuthInfo returns, standing in for an IdP that rejects the flow.
type stubFlow struct {
	name       string
	hint       string
	requestErr error
}

func (s *stubFlow) RequestAuthInfo(context.Context) (AuthFlowInfo, error) {
	if s.requestErr != nil {
		return AuthFlowInfo{}, s.requestErr
	}
	return AuthFlowInfo{UserCode: s.name}, nil
}

func (s *stubFlow) WaitToken(context.Context, AuthFlowInfo) (TokenInfo, error) {
	return TokenInfo{}, nil
}

func (s *stubFlow) GetClientID(context.Context) string {
	return ""
}

// stubInit returns a flow initializer that yields a named stub flow, or err when err is non-nil.
func stubInit(name string, err error) oauthFlowInit {
	return stubInitFlow(name, err, nil)
}

// stubInitFlow is stubInit with control over what the resulting flow's RequestAuthInfo returns.
func stubInitFlow(name string, initErr, requestErr error) oauthFlowInit {
	return oauthFlowInit{
		name: name,
		init: func(_ *Auth, _ *mgm.GrpcClient, hint string) (OAuthFlow, error) {
			if initErr != nil {
				return nil, initErr
			}
			return &stubFlow{name: name, hint: hint, requestErr: requestErr}, nil
		},
	}
}

// stubAuthFactory hands out an Auth without a management connection, which the stub
// initializers above never touch.
func stubAuthFactory(a *Auth) authFactory {
	return func(context.Context) (*Auth, func(), error) {
		return a, func() {}, nil
	}
}

func TestOAuthFlowWithFallback(t *testing.T) {
	notFound := status.Error(codes.NotFound, "no device authorization flow information available")
	unimplemented := status.Error(codes.Unimplemented, "unknown method")
	incompleteConfig := fmt.Errorf("%w: Client ID value is empty", errFlowNotConfigured)
	unreachable := status.Error(codes.Unavailable, "connection refused")

	tests := []struct {
		name          string
		flows         []oauthFlowInit
		expectedFlow  string
		expectedErr   string
		expectedNoSSO bool
	}{
		{
			name:         "preferred flow is used",
			flows:        []oauthFlowInit{stubInit("device", nil), stubInit("pkce", nil)},
			expectedFlow: "device",
		},
		{
			// the RedHat case: device code flow disabled on management, PKCE configured
			name:         "falls back when preferred flow is not configured",
			flows:        []oauthFlowInit{stubInit("device", notFound), stubInit("pkce", nil)},
			expectedFlow: "pkce",
		},
		{
			name:         "falls back on an incomplete flow configuration",
			flows:        []oauthFlowInit{stubInit("pkce", incompleteConfig), stubInit("device", nil)},
			expectedFlow: "device",
		},
		{
			name:        "does not fall back when the preferred flow fails for another reason",
			flows:       []oauthFlowInit{stubInit("pkce", unreachable), stubInit("device", nil)},
			expectedErr: "connection refused",
		},
		{
			// stays neutral about the remedy: --extend and SSH auth cannot use a setup key
			name:          "neither flow configured reports no SSO provider",
			flows:         []oauthFlowInit{stubInit("device", notFound), stubInit("pkce", notFound)},
			expectedErr:   "no SSO provider configured",
			expectedNoSSO: true,
		},
		{
			name:          "old server without the flow RPCs asks for an update",
			flows:         []oauthFlowInit{stubInit("device", unimplemented), stubInit("pkce", unimplemented)},
			expectedErr:   "does not support SSO providers",
			expectedNoSSO: true,
		},
	}

	mgmURL, err := url.Parse("https://api.netbird.io:443")
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Auth{mgmURL: mgmURL}
			flow, err := oauthFlowWithFallback(a, nil, tt.flows, "user@example.com", stubAuthFactory(a))

			if tt.expectedErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr)

				var ssoUnavailable *ssoUnavailableError
				assert.Equal(t, tt.expectedNoSSO, errors.As(err, &ssoUnavailable),
					"terminal SSO-unavailable classification mismatch for %v", err)
				return
			}

			require.NoError(t, err)
			stub := activeStub(t, flow)
			assert.Equal(t, tt.expectedFlow, stub.name)
			assert.Equal(t, "user@example.com", stub.hint, "login hint must be passed to the flow")
		})
	}
}

// activeStub unwraps the flow currently in use, which is behind a fallbackFlow whenever an
// untried flow is left.
func activeStub(t *testing.T, flow OAuthFlow) *stubFlow {
	t.Helper()

	if fallback, ok := flow.(*fallbackFlow); ok {
		flow = fallback.current()
	}

	stub, ok := flow.(*stubFlow)
	require.True(t, ok, "unexpected flow type %T", flow)
	return stub
}

// TestFallbackFlowRequestAuthInfo covers the failure the RedHat report hit: management hands out
// a device flow configuration, but the IdP does not serve the grant and only says so when the
// device code is requested.
func TestFallbackFlowRequestAuthInfo(t *testing.T) {
	mgmURL, err := url.Parse("https://api.netbird.io:443")
	require.NoError(t, err)
	a := &Auth{mgmURL: mgmURL}

	idpRejects := fmt.Errorf("%w: request device code returned status 404", errFlowNotConfigured)

	t.Run("swaps in the untried flow", func(t *testing.T) {
		flows := []oauthFlowInit{stubInitFlow("device", nil, idpRejects), stubInit("pkce", nil)}

		flow, err := oauthFlowWithFallback(a, nil, flows, "", stubAuthFactory(a))
		require.NoError(t, err)
		require.Equal(t, "device", activeStub(t, flow).name)

		info, err := flow.RequestAuthInfo(context.Background())
		require.NoError(t, err)
		assert.Equal(t, "pkce", info.UserCode, "the request must be served by the fallback flow")
		assert.Equal(t, "pkce", activeStub(t, flow).name, "the fallback flow must stay active for WaitToken")
	})

	t.Run("keeps the original error when nothing else is configured", func(t *testing.T) {
		flows := []oauthFlowInit{
			stubInitFlow("device", nil, idpRejects),
			stubInit("pkce", status.Error(codes.NotFound, "no pkce authorization flow information available")),
		}

		flow, err := oauthFlowWithFallback(a, nil, flows, "", stubAuthFactory(a))
		require.NoError(t, err)

		_, err = flow.RequestAuthInfo(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "status 404")
	})

	t.Run("keeps the original error when the fallback cannot reach management", func(t *testing.T) {
		flows := []oauthFlowInit{stubInitFlow("device", nil, idpRejects), stubInit("pkce", nil)}

		unreachable := func(context.Context) (*Auth, func(), error) {
			return nil, nil, errors.New("connect to management: connection refused")
		}

		flow, err := oauthFlowWithFallback(a, nil, flows, "", unreachable)
		require.NoError(t, err)

		_, err = flow.RequestAuthInfo(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "status 404", "the IdP error must survive a failed fallback")
		assert.Equal(t, "device", activeStub(t, flow).name, "a failed fallback must not swap the flow")
	})

	t.Run("does not swap flows on an unrelated failure", func(t *testing.T) {
		flows := []oauthFlowInit{
			stubInitFlow("device", nil, errors.New("timeout talking to the IdP")),
			stubInit("pkce", nil),
		}

		flow, err := oauthFlowWithFallback(a, nil, flows, "", stubAuthFactory(a))
		require.NoError(t, err)

		_, err = flow.RequestAuthInfo(context.Background())
		require.Error(t, err)
		assert.Equal(t, "device", activeStub(t, flow).name, "the preferred flow must stay active")
	})
}

func TestFlowOrder(t *testing.T) {
	assert.Equal(t, "pkce authorization flow", flowOrder(false)[0].name)
	assert.Equal(t, "device code flow", flowOrder(true)[0].name)
	assert.Len(t, flowOrder(false), 2, "both flows must always be attempted")
}

func TestPreferDeviceFlow(t *testing.T) {
	isUnix := runtime.GOOS == "linux" || runtime.GOOS == "freebsd"

	assert.True(t, preferDeviceFlow(true, true), "forced device flow wins over a desktop session")
	assert.Equal(t, isUnix, preferDeviceFlow(false, false), "headless unix hosts prefer the device flow")
	assert.False(t, preferDeviceFlow(false, true), "desktop clients prefer PKCE")
}
