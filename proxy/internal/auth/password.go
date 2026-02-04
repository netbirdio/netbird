package auth

import (
	"net/http"

	"github.com/netbirdio/netbird/shared/management/proto"
)

const (
	passwordUserId = "password-user"
	passwordFormId = "password"
)

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

func (Password) Type() Method {
	return MethodPassword
}

// Authenticate attempts to authenticate the request using a form
// value passed in the request.
// If authentication fails, the required HTTP form ID is returned
// so that it can be injected into a request from the UI so that
// authentication may be successful.
func (p Password) Authenticate(r *http.Request) (string, string) {
	password := r.FormValue(passwordFormId)

	if password == "" {
		// This cannot be authenticated so not worth wasting time sending the request.
		return "", passwordFormId
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
		// TODO: log error here
		return "", passwordFormId
	}

	if res.GetSuccess() {
		return passwordUserId, ""
	}

	return "", passwordFormId
}
