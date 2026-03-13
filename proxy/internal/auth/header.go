package auth

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/netbirdio/netbird/proxy/auth"
	"github.com/netbirdio/netbird/proxy/internal/types"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// ErrHeaderAuthFailed indicates that the header was present but the
// credential did not validate. Callers should return 401 instead of
// falling through to other auth schemes.
var ErrHeaderAuthFailed = errors.New("header authentication failed")

// Header implements header-based authentication. The proxy checks for the
// configured header in each request and validates its value via gRPC.
type Header struct {
	id         types.ServiceID
	accountId  types.AccountID
	headerName string
	client     authenticator
}

// NewHeader creates a Header authentication scheme for the given header name.
func NewHeader(client authenticator, id types.ServiceID, accountId types.AccountID, headerName string) Header {
	return Header{
		id:         id,
		accountId:  accountId,
		headerName: headerName,
		client:     client,
	}
}

// Type returns auth.MethodHeader.
func (Header) Type() auth.Method {
	return auth.MethodHeader
}

// Authenticate checks for the configured header in the request. If absent,
// returns empty (unauthenticated). If present, validates via gRPC.
func (h Header) Authenticate(r *http.Request) (string, string, error) {
	value := r.Header.Get(h.headerName)
	if value == "" {
		return "", "", nil
	}

	res, err := h.client.Authenticate(r.Context(), &proto.AuthenticateRequest{
		Id:        string(h.id),
		AccountId: string(h.accountId),
		Request: &proto.AuthenticateRequest_HeaderAuth{
			HeaderAuth: &proto.HeaderAuthRequest{
				HeaderValue: value,
			},
		},
	})
	if err != nil {
		return "", "", fmt.Errorf("authenticate header: %w", err)
	}

	if res.GetSuccess() {
		return res.GetSessionToken(), "", nil
	}

	return "", "", ErrHeaderAuthFailed
}
