package rest

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/netbirdio/netbird/management/server/http/api"
)

// AccountsAPI APIs for accounts, do not use directly
type AccountsAPI struct {
	c *Client
}

// List list all accounts, only returns one account always
// See more: https://docs.netbird.io/api/resources/accounts#list-all-accounts
func (a *AccountsAPI) List(ctx context.Context) ([]api.Account, error) {
	resp, err := a.c.newRequest(ctx, "GET", "/api/accounts", nil)
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[[]api.Account](resp)
	return ret, err
}

// Update update account settings
// See more: https://docs.netbird.io/api/resources/accounts#update-an-account
func (a *AccountsAPI) Update(ctx context.Context, accountID string, request api.PutApiAccountsAccountIdJSONRequestBody) (*api.Account, error) {
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.newRequest(ctx, "PUT", "/api/accounts/"+accountID, bytes.NewReader(requestBytes))
	if err != nil {
		return nil, err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	ret, err := parseResponse[api.Account](resp)
	return &ret, err
}

// Delete delete account
// See more: https://docs.netbird.io/api/resources/accounts#delete-an-account
func (a *AccountsAPI) Delete(ctx context.Context, accountID string) error {
	resp, err := a.c.newRequest(ctx, "DELETE", "/api/accounts/"+accountID, nil)
	if err != nil {
		return err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}

	return nil
}
