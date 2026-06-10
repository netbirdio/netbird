package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/url"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

// ReverseProxyTokensAPI exposes the account-scoped proxy access tokens that
// self-hosted (bring-your-own-proxy) deployments use to register a
// `netbird proxy` instance with management. Tokens are bound to the
// calling account; revoking a token disconnects every proxy that
// authenticated with it.
type ReverseProxyTokensAPI struct {
	c *Client
}

// List returns every proxy token the calling account has minted, including
// already-revoked entries. The plain token is never returned — only the
// metadata (id, name, created_at, last_used, revoked).
func (a *ReverseProxyTokensAPI) List(ctx context.Context) ([]api.ProxyToken, error) {
	resp, err := a.c.NewRequest(ctx, "GET", "/api/reverse-proxies/proxy-tokens", nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[[]api.ProxyToken](resp)
	return ret, err
}

// Create mints a fresh account-scoped proxy token. The returned
// ProxyTokenCreated.PlainToken is shown only once — callers must persist
// it immediately. Subsequent reads will only expose the token metadata,
// not the secret material.
func (a *ReverseProxyTokensAPI) Create(ctx context.Context, request api.ProxyTokenRequest) (*api.ProxyTokenCreated, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.NewRequest(ctx, "POST", "/api/reverse-proxies/proxy-tokens", bytes.NewReader(requestBytes), nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.ProxyTokenCreated](resp)
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

// Delete revokes a previously-issued proxy token by ID. Revoked tokens
// remain in List output (with revoked=true) so operators can audit which
// credentials existed; the plain secret can no longer authenticate any
// new proxy registration.
func (a *ReverseProxyTokensAPI) Delete(ctx context.Context, tokenID string) error {
	// Guard against the empty input: url.PathEscape("") returns "" which
	// would collapse the request URL onto the collection endpoint and
	// silently delete nothing (or 405 depending on routing).
	if tokenID == "" {
		return errors.New("tokenID is required")
	}
	resp, err := a.c.NewRequest(ctx, "DELETE", "/api/reverse-proxies/proxy-tokens/"+url.PathEscape(tokenID), nil, nil)
	if err != nil {
		return err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	return nil
}
