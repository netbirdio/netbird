package grpc_test

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	servicemanager "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service/manager"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/sessionkey"
	nbgrpc "github.com/netbirdio/netbird/management/internals/shared/grpc"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/proto"
)

func credentialServer(t *testing.T) (*nbgrpc.ProxyServiceServer, context.Context, grpc.UnaryServerInterceptor) {
	t.Helper()
	ctx := context.Background()
	s, err := store.NewStore(ctx, types.SqliteStoreEngine, t.TempDir(), nil, false)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, s.Close(ctx)) })
	require.NoError(t, s.SaveAccount(ctx, &types.Account{Id: "account"}))
	keys, err := sessionkey.GenerateKeyPair()
	require.NoError(t, err)
	for _, id := range []string{"service", "other-service"} {
		svc := &service.Service{
			ID: id, AccountID: "account", Name: id, Domain: id + ".example.com",
			Enabled: true, SessionPrivateKey: keys.PrivateKey, SessionPublicKey: keys.PublicKey,
			Auth: service.AuthConfig{
				PinAuth:      &service.PINAuthConfig{Enabled: true, Pin: "842716"},
				PasswordAuth: &service.PasswordAuthConfig{Enabled: true, Password: "test-password"},
			},
		}
		require.NoError(t, svc.Auth.HashSecrets())
		require.NoError(t, s.CreateService(ctx, svc))
	}
	account := "account"
	token, err := types.CreateNewProxyAccessToken("test proxy", time.Hour, &account, "admin")
	require.NoError(t, err)
	require.NoError(t, s.SaveProxyAccessToken(ctx, &token.ProxyAccessToken))
	ctx = metadata.NewIncomingContext(ctx, metadata.Pairs("authorization", "Bearer "+string(token.PlainToken)))
	ctx = peer.NewContext(ctx, &peer.Peer{Addr: net.TCPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.1:443"))})
	server := nbgrpc.NewProxyServiceServer(nil, nil, nil, nbgrpc.ProxyOIDCConfig{}, nil, nil, nil, nil, nil)
	t.Cleanup(server.Close)
	server.SetServiceManager(servicemanager.NewManager(s, nil, nil, nil, nil, nil))
	interceptor, _, closeInterceptor := nbgrpc.NewProxyAuthInterceptors(s)
	t.Cleanup(closeInterceptor)
	return server, ctx, interceptor
}

func TestAuthenticateCredentialRateLimit(t *testing.T) {
	server, ctx, interceptor := credentialServer(t)
	authenticate := func(req *proto.AuthenticateRequest) (*proto.AuthenticateResponse, error) {
		response, err := interceptor(ctx, req, &grpc.UnaryServerInfo{FullMethod: "/management.ProxyService/Authenticate"}, func(ctx context.Context, req any) (any, error) {
			return server.Authenticate(ctx, req.(*proto.AuthenticateRequest))
		})
		if err != nil {
			return nil, err
		}
		return response.(*proto.AuthenticateResponse), nil
	}
	for i := range 5 {
		req := &proto.AuthenticateRequest{AccountId: "account", Id: "service"}
		if i%2 == 0 {
			req.Request = &proto.AuthenticateRequest_Pin{Pin: &proto.PinRequest{Pin: "000000"}}
		} else {
			req.Request = &proto.AuthenticateRequest_Password{Password: &proto.PasswordRequest{Password: "wrong-password"}}
		}
		resp, err := authenticate(req)
		require.NoError(t, err)
		assert.False(t, resp.GetSuccess(), "incorrect PINs and passwords must be denied")
		assert.Empty(t, resp.GetSessionToken(), "incorrect credentials must not issue a token")
	}
	req := &proto.AuthenticateRequest{AccountId: "account", Id: "service", Request: &proto.AuthenticateRequest_Pin{Pin: &proto.PinRequest{Pin: "842716"}}}
	resp, err := authenticate(req)
	assert.Nil(t, resp, "a throttled verification must not return a session")
	require.Equal(t, codes.ResourceExhausted, status.Code(err), "PIN and password checks must share a service budget even with a valid proxy token")
	details := status.Convert(err).Details()
	require.Len(t, details, 1, "throttled responses must include a retry hint")
	retry, ok := details[0].(*errdetails.RetryInfo)
	require.True(t, ok, "the hint must use the standard RetryInfo message")
	assert.Positive(t, retry.RetryDelay.AsDuration(), "the retry delay must be positive")
	assert.LessOrEqual(t, retry.RetryDelay.AsDuration(), 6*time.Second, "the service must replenish one verification every six seconds")
	req.AccountId = "another-account"
	_, err = authenticate(req)
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "account scope must still be enforced before throttling")
	req.AccountId = "account"
	req.Id = "other-service"
	resp, err = authenticate(req)
	require.NoError(t, err)
	assert.True(t, resp.GetSuccess(), "one service's throttle must not block another service")
	assert.NotEmpty(t, resp.GetSessionToken(), "valid credentials on another service must issue a session")
}

func TestAuthenticateCredentialConcurrentLimit(t *testing.T) {
	server, _, _ := credentialServer(t)
	req := &proto.AuthenticateRequest{AccountId: "account", Id: "service", Request: &proto.AuthenticateRequest_Pin{Pin: &proto.PinRequest{Pin: "000000"}}}
	var checked, throttled atomic.Int32
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			resp, err := server.Authenticate(context.Background(), req)
			switch status.Code(err) {
			case codes.OK:
				checked.Add(1)
				assert.False(t, resp.GetSuccess(), "incorrect credentials must be denied")
			case codes.ResourceExhausted:
				throttled.Add(1)
			default:
				assert.NoError(t, err)
			}
		})
	}
	wg.Wait()
	assert.EqualValues(t, 5, checked.Load(), "only the burst budget may reach concurrent credential verification")
	assert.EqualValues(t, 15, throttled.Load(), "excess concurrent checks must be throttled")
}
