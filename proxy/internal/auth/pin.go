package auth

import (
	"fmt"
	"net/http"

	"github.com/netbirdio/netbird/proxy/auth"
	"github.com/netbirdio/netbird/shared/management/proto"
)

const pinFormId = "pin"

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

func (Pin) Type() auth.Method {
	return auth.MethodPIN
}

// Authenticate attempts to authenticate the request using a form
// value passed in the request.
// If authentication fails, the required HTTP form ID is returned
// so that it can be injected into a request from the UI so that
// authentication may be successful.
func (p Pin) Authenticate(r *http.Request) (string, string, error) {
	pin := r.FormValue(pinFormId)

	if pin == "" {
		// No PIN submitted; return the form ID so the UI can prompt the user.
		return "", pinFormId, nil
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
		return "", "", fmt.Errorf("authenticate pin: %w", err)
	}

	if res.GetSuccess() {
		return res.GetSessionToken(), "", nil
	}

	return "", pinFormId, nil
}
