package rest

import "net/http"

// Option modifier for creation of Client
type Option func(*Client)

// HTTPClient interface for HTTP client
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// WithHTTPClient overrides HTTPClient used
func WithHTTPClient(client HTTPClient) Option {
	return func(c *Client) {
		c.httpClient = client
	}
}

// WithBearerToken uses provided bearer token acquired from SSO for authentication
func WithBearerToken(token string) Option {
	return WithAuthHeader("Bearer " + token)
}

// WithPAT uses provided Personal Access Token
// (created from NetBird Management Dashboard) for authentication
func WithPAT(token string) Option {
	return WithAuthHeader("Token " + token)
}

// WithManagementURL overrides target NetBird Management server
func WithManagementURL(url string) Option {
	return func(c *Client) {
		c.managementURL = url
	}
}

// WithAuthHeader overrides auth header completely, this should generally not be used
// and WithBearerToken or WithPAT should be used instead
func WithAuthHeader(value string) Option {
	return func(c *Client) {
		c.authHeader = value
	}
}

// WithAccount uses impersonated account for Client
func WithAccount(value string) Option {
	return func(c *Client) {
		c.impersonatedAccount = value
	}
}
