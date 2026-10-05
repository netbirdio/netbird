package rest

import "net/http"

// option modifier for creation of Client
type option func(*Client)

// HTTPClient interface for HTTP client
type HttpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// WithHTTPClient overrides HTTPClient used
func WithHttpClient(client HttpClient) option {
	return func(c *Client) {
		c.httpClient = client
	}
}

// WithBearerToken uses provided bearer token acquired from SSO for authentication
func WithBearerToken(token string) option {
	return WithAuthHeader("Bearer " + token)
}

// WithPAT uses provided Personal Access Token
// (created from NetBird Management Dashboard) for authentication
func WithPAT(token string) option {
	return WithAuthHeader("Token " + token)
}

// WithManagementURL overrides target NetBird Management server
func WithManagementURL(url string) option {
	return func(c *Client) {
		c.managementURL = url
	}
}

// WithAuthHeader overrides auth header completely, this should generally not be used
// and WithBearerToken or WithPAT should be used instead
func WithAuthHeader(value string) option {
	return func(c *Client) {
		c.authHeader = value
	}
}

// WithUserAgent sets a custom User-Agent header for HTTP requests
func WithUserAgent(userAgent string) option {
	return func(c *Client) {
		c.userAgent = userAgent
	}
}
