package rest

import "net/http"

type option func(*Client)

type HttpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

func WithHttpClient(client HttpClient) option {
	return func(c *Client) {
		c.httpClient = client
	}
}

func WithBearerToken(token string) option {
	return WithAuthHeader("Bearer " + token)
}

func WithPAT(token string) option {
	return WithAuthHeader("Token " + token)
}

func WithManagementURL(url string) option {
	return func(c *Client) {
		c.managementURL = url
	}
}

func WithAuthHeader(value string) option {
	return func(c *Client) {
		c.authHeader = value
	}
}
