package auth

import (
	"net/http"

	"github.com/netbirdio/netbird/shared/management/proto"
)

const (
	pinUserId = "pin-user"
	pinFormId = "pin"
)

type Pin struct {
	id, accountId string
	client        authenticator
}

func NewPin(client authenticator, id, accountId string) Pin {
	return Pin{
		id:        id,
		accountId: accountId,
		client:    client,
	}
}

func (Pin) Type() Method {
	return MethodPIN
}

// Authenticate attempts to authenticate the request using a form
// value passed in the request.
// If authentication fails, the required HTTP form ID is returned
// so that it can be injected into a request from the UI so that
// authentication may be successful.
func (p Pin) Authenticate(r *http.Request) (string, string) {
	pin := r.FormValue(pinFormId)

	if pin == "" {
		// This cannot be authenticated so not worth wasting time sending the request.
		return "", pinFormId
	}

	res, err := p.client.Authenticate(r.Context(), &proto.AuthenticateRequest{
		Id:        p.id,
		AccountId: p.accountId,
		Request: &proto.AuthenticateRequest_Pin{
			Pin: &proto.PinRequest{
				Pin: pin,
			},
		},
	})
	if err != nil {
		// TODO: log error here
		return "", pinFormId
	}

	if res.GetSuccess() {
		return pinUserId, ""
	}

	return "", pinFormId
}
