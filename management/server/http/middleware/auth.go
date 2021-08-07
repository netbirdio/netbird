package middleware

import (
	"context"
	"golang.org/x/oauth2"
	"log"

	"github.com/coreos/go-oidc"
)

type Authenticator struct {
	Provider *oidc.Provider
	Config   oauth2.Config
	Ctx      context.Context
}

func NewAuthenticator(authDomain string, authClientId string, authClientSecret string, authCallback string) (*Authenticator, error) {
	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, "https://"+authDomain+"/")
	if err != nil {
		log.Printf("failed to get provider: %v", err)
		return nil, err
	}

	conf := oauth2.Config{
		ClientID:     authClientId,
		ClientSecret: authClientSecret,
		RedirectURL:  authCallback,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "email_verified"},
	}

	return &Authenticator{
		Provider: provider,
		Config:   conf,
		Ctx:      ctx,
	}, nil
}
