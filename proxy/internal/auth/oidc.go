package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/proxy/auth"
	"github.com/netbirdio/netbird/shared/management/proto"
)

type urlGenerator interface {
	GetOIDCURL(context.Context, *proto.GetOIDCURLRequest, ...grpc.CallOption) (*proto.GetOIDCURLResponse, error)
}

type OIDC struct {
	id             string
	accountId      string
	forwardedProto string
	client         urlGenerator
}

// NewOIDC creates a new OIDC authentication scheme
func NewOIDC(client urlGenerator, id, accountId, forwardedProto string) OIDC {
	return OIDC{
		id:             id,
		accountId:      accountId,
		forwardedProto: forwardedProto,
		client:         client,
	}
}

func (OIDC) Type() auth.Method {
	return auth.MethodOIDC
}

// Authenticate checks for an OIDC session token or obtains the OIDC redirect URL.
func (o OIDC) Authenticate(r *http.Request) (string, string, error) {
	// Check for the session_token query param (from OIDC redirects).
	// The management server passes the token in the URL because it cannot set
	// cookies for the proxy's domain (cookies are domain-scoped per RFC 6265).
	if token := r.URL.Query().Get("session_token"); token != "" {
		return token, "", nil
	}

	redirectURL := &url.URL{
		Scheme: auth.ResolveProto(o.forwardedProto, r.TLS),
		Host:   r.Host,
		Path:   r.URL.Path,
	}

	res, err := o.client.GetOIDCURL(r.Context(), &proto.GetOIDCURLRequest{
		Id:          o.id,
		AccountId:   o.accountId,
		RedirectUrl: redirectURL.String(),
	})
	if err != nil {
		return "", "", fmt.Errorf("get OIDC URL: %w", err)
	}

	return "", res.GetUrl(), nil
}
