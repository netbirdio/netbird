package grpc

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
	"github.com/netbirdio/netbird/management/server/types"
)

// capturingAuthorizer records the arguments of the last AuthorizeProxyConnect
// call and returns a fixed error.
type capturingAuthorizer struct {
	called  int
	token   *types.ProxyAccessToken
	proxyID string
	address string
	err     error
}

func (a *capturingAuthorizer) AuthorizeProxyConnect(_ context.Context, token *types.ProxyAccessToken, proxyID, address string) error {
	a.called++
	a.token = token
	a.proxyID = proxyID
	a.address = address
	return a.err
}

// authorizerServer builds a ProxyServiceServer whose proxy manager reports
// every cluster address as available, so the authorizer is the only thing
// standing between a claim and success.
func authorizerServer(t *testing.T) *ProxyServiceServer {
	t.Helper()
	ctrl := gomock.NewController(t)
	mgr := proxy.NewMockManager(ctrl)
	mgr.EXPECT().IsClusterAddressAvailable(gomock.Any(), gomock.Any(), gomock.Any()).Return(true, nil).AnyTimes()
	return &ProxyServiceServer{proxyManager: mgr}
}

// TestValidateProxyConnect_NilAuthorizerUnchanged guards the no-behavior-change
// claim: with no authorizer installed — the OSS default — a well-formed claim
// succeeds and malformed input is rejected exactly as before the hook existed.
func TestValidateProxyConnect_NilAuthorizerUnchanged(t *testing.T) {
	s := authorizerServer(t)

	params, err := s.validateProxyConnect("proxy-1", "cluster.example.com", scopedCtx("acc-1"))
	require.NoError(t, err)
	assert.Equal(t, "proxy-1", params.proxyID)
	assert.Equal(t, "cluster.example.com", params.address)

	_, err = s.validateProxyConnect("", "cluster.example.com", scopedCtx("acc-1"))
	require.Error(t, err)
	st, ok := grpcstatus.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code(), "missing proxy_id must stay InvalidArgument")

	_, err = s.validateProxyConnect("proxy-1", "not a hostname", scopedCtx("acc-1"))
	require.Error(t, err)
	st, ok = grpcstatus.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code(), "invalid address must stay InvalidArgument")
}

// TestValidateProxyConnect_AuthorizerReceivesClaim pins the hook contract: the
// authorizer sees the presented token and the claimed proxy ID and address,
// and an authorized claim proceeds.
func TestValidateProxyConnect_AuthorizerReceivesClaim(t *testing.T) {
	s := authorizerServer(t)
	auth := &capturingAuthorizer{}
	s.SetProxyConnectAuthorizer(auth)

	params, err := s.validateProxyConnect("proxy-1", "cluster.example.com", scopedCtx("acc-1"))
	require.NoError(t, err)
	assert.Equal(t, "cluster.example.com", params.address)

	require.Equal(t, 1, auth.called, "authorizer must be consulted exactly once per connect")
	assert.Equal(t, "proxy-1", auth.proxyID)
	assert.Equal(t, "cluster.example.com", auth.address)
	require.NotNil(t, auth.token, "the presented token must be handed to the authorizer")
	require.NotNil(t, auth.token.AccountID)
	assert.Equal(t, "acc-1", *auth.token.AccountID)
}

// TestValidateProxyConnect_PlainErrorBecomesPermissionDenied pins the error
// mapping: a non-status error from the authorizer surfaces as
// PermissionDenied — distinguishable from the AlreadyExists used for address
// conflicts — and the claim does not proceed even though the address itself
// was available.
func TestValidateProxyConnect_PlainErrorBecomesPermissionDenied(t *testing.T) {
	s := authorizerServer(t)
	s.SetProxyConnectAuthorizer(&capturingAuthorizer{err: errors.New("not the assigned credential")})

	_, err := s.validateProxyConnect("proxy-1", "cluster.example.com", scopedCtx("acc-1"))
	require.Error(t, err)
	st, ok := grpcstatus.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.PermissionDenied, st.Code())
	assert.Contains(t, st.Message(), "not the assigned credential", "the authorizer's reason must survive into the status message")
}

// TestValidateProxyConnect_StatusErrorPassesThrough pins that an authorizer
// which chooses its own status code is not second-guessed.
func TestValidateProxyConnect_StatusErrorPassesThrough(t *testing.T) {
	s := authorizerServer(t)
	s.SetProxyConnectAuthorizer(&capturingAuthorizer{
		err: grpcstatus.Errorf(codes.ResourceExhausted, "try later"),
	})

	_, err := s.validateProxyConnect("proxy-1", "cluster.example.com", scopedCtx("acc-1"))
	require.Error(t, err)
	st, ok := grpcstatus.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.ResourceExhausted, st.Code(), "a status error must pass through unchanged")
	assert.Equal(t, "try later", st.Message())
}

// TestValidateProxyConnect_AuthorizerSeesGlobalAndTokenlessConnects pins the
// call-site placement: the authorizer sits outside the account-scoped branch,
// so management-wide tokens (AccountID == nil) and connections without any
// token are also presented to it rather than bypassing policy.
func TestValidateProxyConnect_AuthorizerSeesGlobalAndTokenlessConnects(t *testing.T) {
	s := &ProxyServiceServer{} // no proxy manager: neither path may reach the availability check

	auth := &capturingAuthorizer{}
	s.SetProxyConnectAuthorizer(auth)

	_, err := s.validateProxyConnect("proxy-1", "cluster.example.com", globalCtx())
	require.NoError(t, err)
	require.Equal(t, 1, auth.called, "a management-wide token must still be presented to the authorizer")
	require.NotNil(t, auth.token)
	assert.Nil(t, auth.token.AccountID)

	_, err = s.validateProxyConnect("proxy-1", "cluster.example.com", context.Background())
	require.NoError(t, err)
	require.Equal(t, 2, auth.called, "a token-less connect must still be presented to the authorizer")
	assert.Nil(t, auth.token, "no token in context must surface as a nil token, not a zero value")
}

// TestValidateProxyConnect_AuthorizerRunsLast pins the ordering: input
// validation and the availability check precede policy, so the authorizer is
// never consulted about a claim that is malformed or already rejected.
func TestValidateProxyConnect_AuthorizerRunsLast(t *testing.T) {
	ctrl := gomock.NewController(t)
	mgr := proxy.NewMockManager(ctrl)
	mgr.EXPECT().IsClusterAddressAvailable(gomock.Any(), gomock.Any(), gomock.Any()).Return(false, nil)
	s := &ProxyServiceServer{proxyManager: mgr}

	auth := &capturingAuthorizer{}
	s.SetProxyConnectAuthorizer(auth)

	_, err := s.validateProxyConnect("proxy-1", "not a hostname", scopedCtx("acc-1"))
	require.Error(t, err)
	assert.Zero(t, auth.called, "a malformed address must be rejected before policy runs")

	_, err = s.validateProxyConnect("proxy-1", "cluster.example.com", scopedCtx("acc-1"))
	require.Error(t, err)
	st, ok := grpcstatus.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.AlreadyExists, st.Code(), "an address conflict must keep its own status")
	assert.Zero(t, auth.called, "a conflicting address must be rejected before policy runs")
}
