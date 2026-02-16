package auth

import (
	"fmt"
	"net/http"

	"github.com/netbirdio/netbird/proxy/auth"
	"github.com/netbirdio/netbird/shared/management/proto"
)

const passwordFormId = "password"

type Password struct {
	id, accountId string
	client        authenticator
}

func NewPassword(client authenticator, id, accountId string) Password {
	return Password{
		id:        id,
		accountId: accountId,
		client:    client,
	}
}

func (Password) Type() auth.Method {
	return auth.MethodPassword
}

// Authenticate attempts to authenticate the request using a form
// value passed in the request.
// If authentication fails, the required HTTP form ID is returned
// so that it can be injected into a request from the UI so that
// authentication may be successful.
func (p Password) Authenticate(r *http.Request) (string, string, error) {
	password := r.FormValue(passwordFormId)

	if password == "" {
		// No password submitted; return the form ID so the UI can prompt the user.
		return "", passwordFormId, nil
	}

	res, err := p.client.Authenticate(r.Context(), &proto.AuthenticateRequest{
		Id:        p.id,
		AccountId: p.accountId,
		Request: &proto.AuthenticateRequest_Password{
			Password: &proto.PasswordRequest{
				Password: password,
			},
		},
	})
	if err != nil {
		return "", "", fmt.Errorf("authenticate password: %w", err)
	}

	if res.GetSuccess() {
		return res.GetSessionToken(), "", nil
	}

	return "", passwordFormId, nil
}
