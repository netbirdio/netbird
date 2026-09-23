package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/shared/management/proto"
)

type recordingOIDCURLClient struct {
	request *proto.GetOIDCURLRequest
}

func (c *recordingOIDCURLClient) GetOIDCURL(_ context.Context, request *proto.GetOIDCURLRequest, _ ...grpc.CallOption) (*proto.GetOIDCURLResponse, error) {
	c.request = request
	return &proto.GetOIDCURLResponse{Url: "https://idp.example/authorize"}, nil
}

func TestOIDCRedirectUsesCanonicalAuthority(t *testing.T) {
	client := &recordingOIDCURLClient{}
	scheme := NewOIDC(client, "svc", "acct", "https")
	req := httptest.NewRequest(http.MethodGet, "https://example.com/callback", nil)
	req.Host = "EXAMPLE.COM.:8443"

	_, _, err := scheme.Authenticate(req)
	require.NoError(t, err)
	require.NotNil(t, client.request)
	require.Equal(t, "https://example.com:8443/callback", client.request.GetRedirectUrl())
}
