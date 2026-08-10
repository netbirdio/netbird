package grpc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	proxyauth "github.com/netbirdio/netbird/proxy/auth"
	"github.com/netbirdio/netbird/shared/hash/argon2id"
	"github.com/netbirdio/netbird/shared/management/proto"
)

const authAttemptsHeaderName = "X-API-Key"

func newAuthAttemptsTestServer(t *testing.T) *ProxyServiceServer {
	t.Helper()

	firstHash, err := argon2id.Hash("first-key")
	require.NoError(t, err)
	secondHash, err := argon2id.Hash("second-key")
	require.NoError(t, err)

	svc := &rpservice.Service{
		ID:     "svc1",
		Domain: "example.com",
		Auth: rpservice.AuthConfig{
			HeaderAuths: []*rpservice.HeaderAuthConfig{
				{Enabled: true, Header: authAttemptsHeaderName, Value: firstHash},
				{Enabled: true, Header: authAttemptsHeaderName, Value: secondHash},
			},
		},
	}

	ctrl := gomock.NewController(t)
	mgr := rpservice.NewMockManager(ctrl)
	mgr.EXPECT().GetServiceByID(gomock.Any(), gomock.Any(), gomock.Any()).Return(svc, nil).AnyTimes()

	limiter := newAuthFailureLimiter()
	t.Cleanup(limiter.stop)
	clientLimiter := newAuthClientLimiter()
	t.Cleanup(clientLimiter.stop)

	mac := make([]byte, sha256.Size)
	_, err = rand.Read(mac)
	require.NoError(t, err)

	return &ProxyServiceServer{
		serviceManager:     mgr,
		authAttemptLimiter: limiter,
		authClientLimiter:  clientLimiter,
		authFailureMAC:     mac,
	}
}

func clientIPContext(ip string) context.Context {
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs(proxyauth.ClientIPMetadataKey, ip))
}

func authAttemptsRequest(credential string) *proto.AuthenticateRequest {
	return &proto.AuthenticateRequest{
		Id:        "svc1",
		AccountId: "acc1",
		Request: &proto.AuthenticateRequest_HeaderAuth{
			HeaderAuth: &proto.HeaderAuthRequest{
				HeaderName:  authAttemptsHeaderName,
				HeaderValue: credential,
			},
		},
	}
}

func TestAuthenticate_ValidCredentialIsNeverRateLimited(t *testing.T) {
	s := newAuthAttemptsTestServer(t)

	for i := 0; i < proxyAuthFailureBurst*2; i++ {
		resp, err := s.Authenticate(context.Background(), authAttemptsRequest("first-key"))
		require.NoError(t, err, "a valid credential must never be throttled (attempt %d)", i)
		require.True(t, resp.GetSuccess())
	}
}

func TestAuthenticate_FailedCredentialIsRateLimited(t *testing.T) {
	s := newAuthAttemptsTestServer(t)

	for i := 0; i < proxyAuthFailureBurst; i++ {
		resp, err := s.Authenticate(context.Background(), authAttemptsRequest("wrong-key"))
		require.NoError(t, err, "attempt %d should be within the failure budget", i)
		require.False(t, resp.GetSuccess())
	}

	_, err := s.Authenticate(context.Background(), authAttemptsRequest("wrong-key"))
	require.Error(t, err)
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))
}

func TestAuthenticate_ThrottledCredentialDoesNotAffectOthers(t *testing.T) {
	s := newAuthAttemptsTestServer(t)

	for i := 0; i < proxyAuthFailureBurst+2; i++ {
		_, _ = s.Authenticate(context.Background(), authAttemptsRequest("wrong-key"))
	}

	resp, err := s.Authenticate(context.Background(), authAttemptsRequest("first-key"))
	require.NoError(t, err, "one throttled credential must not block a valid one")
	assert.True(t, resp.GetSuccess())

	resp, err = s.Authenticate(context.Background(), authAttemptsRequest("second-key"))
	require.NoError(t, err)
	assert.True(t, resp.GetSuccess())

	_, err = s.Authenticate(context.Background(), authAttemptsRequest("another-wrong-key"))
	require.NoError(t, err, "a different failing credential has its own budget")
}

func TestAuthenticate_DistinctCredentialsThrottledPerClient(t *testing.T) {
	const budget = 3

	s := newAuthAttemptsTestServer(t)
	s.authClientLimiter.stop()
	s.authClientLimiter = newAuthLimiter(rate.Every(time.Hour), budget)
	t.Cleanup(s.authClientLimiter.stop)

	ctx := clientIPContext("198.51.100.7")

	for i := 0; i < budget; i++ {
		resp, err := s.Authenticate(ctx, authAttemptsRequest(fmt.Sprintf("garbage-%d", i)))
		require.NoError(t, err, "attempt %d should be within the client budget", i)
		require.False(t, resp.GetSuccess())
	}

	_, err := s.Authenticate(ctx, authAttemptsRequest("garbage-final"))
	require.Error(t, err, "a client rotating distinct credentials must be throttled")
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))

	other := clientIPContext("198.51.100.8")
	resp, err := s.Authenticate(other, authAttemptsRequest("first-key"))
	require.NoError(t, err, "a different client must be unaffected")
	assert.True(t, resp.GetSuccess())
}

func TestAuthenticate_OneStaleCredentialDoesNotExhaustSharedClientBudget(t *testing.T) {
	s := newAuthAttemptsTestServer(t)
	ctx := clientIPContext("198.51.100.9")

	for i := 0; i < proxyAuthFailureBurst*4; i++ {
		_, _ = s.Authenticate(ctx, authAttemptsRequest("stale-key"))
	}

	resp, err := s.Authenticate(ctx, authAttemptsRequest("first-key"))
	require.NoError(t, err, "one client stuck on a stale key must not block others behind the same NAT")
	assert.True(t, resp.GetSuccess())
}

func TestAuthenticate_ProxyWithoutClientIPIsNotClientLimited(t *testing.T) {
	s := newAuthAttemptsTestServer(t)

	for i := 0; i < proxyAuthFailureBurst*2; i++ {
		_, _ = s.Authenticate(context.Background(), authAttemptsRequest(fmt.Sprintf("garbage-%d", i)))
	}

	resp, err := s.Authenticate(context.Background(), authAttemptsRequest("first-key"))
	require.NoError(t, err, "an old proxy must not have its clients share one budget")
	assert.True(t, resp.GetSuccess())
}

func TestAuthenticate_MalformedClientIPIsIgnored(t *testing.T) {
	s := newAuthAttemptsTestServer(t)
	ctx := clientIPContext("not-an-ip")

	for i := 0; i < proxyAuthFailureBurst*2; i++ {
		_, _ = s.Authenticate(ctx, authAttemptsRequest(fmt.Sprintf("garbage-%d", i)))
	}

	resp, err := s.Authenticate(ctx, authAttemptsRequest("first-key"))
	require.NoError(t, err)
	assert.True(t, resp.GetSuccess())
}
