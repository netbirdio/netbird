package rest

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/netbirdio/netbird/management/server/http/api"
)

// TokensAPI APIs for PATs, do not use directly
type TokensAPI struct {
	c *Client
}

// List list user tokens
// See more: https://docs.netbird.io/api/resources/tokens#list-all-tokens
func (a *TokensAPI) List(ctx context.Context, userID string) ([]api.PersonalAccessToken, error) {
	resp, err := a.c.newRequest(ctx, "GET", "/api/users/"+userID+"/tokens", nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[[]api.PersonalAccessToken](resp)
	return ret, err
}

// Get get user token info
// See more: https://docs.netbird.io/api/resources/tokens#retrieve-a-token
func (a *TokensAPI) Get(ctx context.Context, userID, tokenID string) (*api.PersonalAccessToken, error) {
	resp, err := a.c.newRequest(ctx, "GET", "/api/users/"+userID+"/tokens/"+tokenID, nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.PersonalAccessToken](resp)
	return &ret, err
}

// Create generate new PAT for user
// See more: https://docs.netbird.io/api/resources/tokens#create-a-token
func (a *TokensAPI) Create(ctx context.Context, userID string, request api.PostApiUsersUserIdTokensJSONRequestBody) (*api.PersonalAccessTokenGenerated, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.newRequest(ctx, "POST", "/api/users/"+userID+"/tokens", bytes.NewReader(requestBytes))
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.PersonalAccessTokenGenerated](resp)
	return &ret, err
}

// Delete delete user token
// See more: https://docs.netbird.io/api/resources/tokens#delete-a-token
func (a *TokensAPI) Delete(ctx context.Context, userID, tokenID string) error {
	resp, err := a.c.newRequest(ctx, "DELETE", "/api/users/"+userID+"/tokens/"+tokenID, nil)
	if err != nil {
		return err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}

	return nil
}
