package auth

import (
	"net/http"

	"github.com/netbirdio/netbird/shared/management/proto"
)

const linkFormId = "email"

type Link struct {
	id, accountId string
	client        authenticator
}

func NewLink(client authenticator, id, accountId string) Link {
	return Link{
		id:        id,
		accountId: accountId,
		client:    client,
	}
}

func (Link) Type() Method {
	return MethodLink
}

func (l Link) Authenticate(r *http.Request) (string, string) {
	email := r.FormValue(linkFormId)

	res, err := l.client.Authenticate(r.Context(), &proto.AuthenticateRequest{
		Id:        l.id,
		AccountId: l.accountId,
		Request: &proto.AuthenticateRequest_Link{
			Link: &proto.LinkRequest{
				Email:    email,
				Redirect: "", // TODO: calculate this.
			},
		},
	})
	if err != nil {
		// TODO: log error here
		return "", linkFormId
	}

	if res.GetSuccess() {
		// Use the email address as the user identifier.
		return email, ""
	}

	return "", linkFormId
}
