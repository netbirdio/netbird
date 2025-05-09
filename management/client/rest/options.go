package rest

import "net/http"

type option func(*Client)

func WithHttpClient(client *http.Client) option {
	return func(c *Client) {
		c.httpClient = client
	}
}
