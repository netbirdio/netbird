package rest

import (
	"net/http"
	"net/url"
)

// Impersonate returns a Client impersonated for a specific account
func (c *Client) Impersonate(account string) *Client {
	client := NewWithOptions(
		WithManagementURL(c.managementURL),
		WithAuthHeader(c.authHeader),
		WithHttpClient(newImpersonatedHttpClient(account)),
	)
	return client
}

type impersonatedHttpClient struct {
	baseClient *http.Client
	account    string
}

func newImpersonatedHttpClient(account string) *impersonatedHttpClient {
	return &impersonatedHttpClient{
		baseClient: http.DefaultClient,
		account:    account,
	}
}

func (c *impersonatedHttpClient) Do(req *http.Request) (*http.Response, error) {
	parsedURL, err := url.Parse(req.URL.String())
	if err != nil {
		return nil, err
	}

	query := parsedURL.Query()
	query.Set("account", c.account)
	parsedURL.RawQuery = query.Encode()

	req.URL = parsedURL

	return c.baseClient.Do(req)
}
