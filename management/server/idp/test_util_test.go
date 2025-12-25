package idp

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"
)

// mockHTTPClient is a mock implementation of ManagerHTTPClient for testing
type mockHTTPClient struct {
	code    int
	resBody string
	reqBody string
	err     error
}

func (c *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if c.err != nil {
		return nil, c.err
	}

	if req.Body != nil {
		body, _ := io.ReadAll(req.Body)
		c.reqBody = string(body)
	}

	return &http.Response{
		StatusCode: c.code,
		Body:       io.NopCloser(bytes.NewReader([]byte(c.resBody))),
	}, nil
}

// newTestJWT creates a test JWT token with the given expiration time in seconds
func newTestJWT(t *testing.T, expiresIn int) string {
	t.Helper()

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	exp := time.Now().Add(time.Duration(expiresIn) * time.Second).Unix()
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, exp)))
	signature := base64.RawURLEncoding.EncodeToString([]byte("test-signature"))

	return fmt.Sprintf("%s.%s.%s", header, payload, signature)
}
