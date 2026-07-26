package modeldiscovery

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiscoverOpenAIModels(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/gateway/v1/models", r.URL.Path)
		assert.Empty(t, r.URL.RawQuery)
		assert.Equal(t, "application/json", r.Header.Get("Accept"))
		assert.Equal(t, "Bearer secret", r.Header.Get("Authorization"))
		_, _ = io.WriteString(w, `{
			"object": "list",
			"data": [
				{"id": " qwen2.5:latest ", "owned_by": "ignored"},
				{"id": "llama3.2:latest"},
				{"id": "llama3.2:latest"},
				{"id": ""},
				{"id": "bad\u0000id"}
			]
		}`)
	}))
	defer server.Close()

	discoverer := newWithTransport(http.DefaultTransport)
	result, err := discoverer.Discover(context.Background(), Request{
		UpstreamURL:     server.URL + "/gateway/?ignored=true#fragment",
		AuthHeaderName:  "authorization",
		AuthHeaderValue: "Bearer secret",
	})
	require.NoError(t, err)
	assert.Equal(t, SourceOpenAIV1Models, result.Source)
	assert.Equal(t, []Model{
		{ID: "llama3.2:latest", Label: "llama3.2:latest"},
		{ID: "qwen2.5:latest", Label: "qwen2.5:latest"},
	}, result.Models)
}

func TestDiscoverOllamaFallback(t *testing.T) {
	t.Parallel()

	var primaryCalls atomic.Int32
	var fallbackCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/models":
			primaryCalls.Add(1)
			http.NotFound(w, r)
		case "/api/tags":
			fallbackCalls.Add(1)
			_, _ = io.WriteString(w, `{
				"models": [
					{"name": "ignored-name", "model": "gemma3:latest"},
					{"name": "llama3.2:latest", "model": ""}
				]
			}`)
		default:
			http.Error(w, "unexpected path", http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	result, err := newWithTransport(http.DefaultTransport).Discover(context.Background(), Request{
		UpstreamURL:         server.URL,
		AllowOllamaFallback: true,
	})
	require.NoError(t, err)
	assert.Equal(t, int32(1), primaryCalls.Load())
	assert.Equal(t, int32(1), fallbackCalls.Load())
	assert.Equal(t, SourceOllamaAPITags, result.Source)
	assert.Equal(t, []Model{
		{ID: "gemma3:latest", Label: "gemma3:latest"},
		{ID: "llama3.2:latest", Label: "llama3.2:latest"},
	}, result.Models)
}

func TestDiscoverDoesNotFallbackOnAuthenticationFailure(t *testing.T) {
	t.Parallel()

	var fallbackCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/tags" {
			fallbackCalls.Add(1)
		}
		http.Error(w, "secret upstream body", http.StatusUnauthorized)
	}))
	defer server.Close()

	_, err := newWithTransport(http.DefaultTransport).Discover(context.Background(), Request{
		UpstreamURL:         server.URL,
		AllowOllamaFallback: true,
	})
	require.EqualError(t, err, "upstream returned HTTP 401")
	assert.Zero(t, fallbackCalls.Load())
	assert.NotContains(t, err.Error(), "secret upstream body")
	assert.NotContains(t, err.Error(), server.URL)
}

func TestDiscoverDoesNotFollowRedirectsOrLeakAuth(t *testing.T) {
	t.Parallel()

	var redirectedCalls atomic.Int32
	redirected := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectedCalls.Add(1)
		assert.Empty(t, r.Header.Get("Authorization"))
		_, _ = io.WriteString(w, `{"data":[]}`)
	}))
	defer redirected.Close()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirected.URL+"/captured", http.StatusFound)
	}))
	defer server.Close()

	_, err := newWithTransport(http.DefaultTransport).Discover(context.Background(), Request{
		UpstreamURL:     server.URL,
		AuthHeaderName:  "Authorization",
		AuthHeaderValue: "Bearer must-not-leak",
	})
	require.EqualError(t, err, "upstream returned HTTP 302")
	assert.Zero(t, redirectedCalls.Load())
}

func TestDiscoverEnforcesResponseLimit(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"data":[{"id":"llama3.2:latest"}]}`)
	}))
	defer server.Close()

	discoverer := newWithTransport(http.DefaultTransport)
	discoverer.bodyLimit = 16
	_, err := discoverer.Discover(context.Background(), Request{UpstreamURL: server.URL})
	require.EqualError(t, err, "model discovery response is too large")
}

func TestDiscoverEnforcesTimeout(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(time.Second):
			_, _ = io.WriteString(w, `{"data":[]}`)
		}
	}))
	defer server.Close()

	discoverer := newWithTransport(http.DefaultTransport)
	discoverer.timeout = 30 * time.Millisecond
	_, err := discoverer.Discover(context.Background(), Request{UpstreamURL: server.URL})
	require.EqualError(t, err, "model discovery timed out")
}

func TestDiscoverHonorsSkipTLSVerification(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"data":[]}`)
	}))
	defer server.Close()

	discoverer := New(nil)
	_, err := discoverer.Discover(context.Background(), Request{UpstreamURL: server.URL})
	require.EqualError(t, err, "model discovery request failed")

	result, err := discoverer.Discover(context.Background(), Request{
		UpstreamURL:   server.URL,
		SkipTLSVerify: true,
	})
	require.NoError(t, err)
	assert.Empty(t, result.Models)
}

func TestDiscoverRejectsUnsafeRequestValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		request Request
		wantErr string
	}{
		{
			name:    "unsupported scheme",
			request: Request{UpstreamURL: "file:///etc/passwd"},
			wantErr: "model discovery upstream URL is invalid",
		},
		{
			name:    "URL credentials",
			request: Request{UpstreamURL: "http://user:pass@example.com"},
			wantErr: "model discovery upstream URL must not contain credentials",
		},
		{
			name:    "missing hostname",
			request: Request{UpstreamURL: "http://:11434"},
			wantErr: "model discovery upstream URL is invalid",
		},
		{
			name: "incomplete auth header",
			request: Request{
				UpstreamURL:    "http://example.com",
				AuthHeaderName: "Authorization",
			},
			wantErr: "model discovery authentication header is incomplete",
		},
		{
			name: "header injection",
			request: Request{
				UpstreamURL:     "http://example.com",
				AuthHeaderName:  "Authorization",
				AuthHeaderValue: "Bearer safe\r\nX-Evil: yes",
			},
			wantErr: "model discovery authentication header is invalid",
		},
		{
			name: "unsupported auth header",
			request: Request{
				UpstreamURL:     "http://example.com",
				AuthHeaderName:  "X-API-Key",
				AuthHeaderValue: "secret",
			},
			wantErr: "model discovery authentication header is unsupported",
		},
		{
			name: "oversized URL",
			request: Request{
				UpstreamURL: "http://example.com/" + strings.Repeat("a", maxUpstreamURLBytes),
			},
			wantErr: "model discovery upstream URL is too long",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := newWithTransport(http.DefaultTransport).Discover(context.Background(), test.request)
			require.EqualError(t, err, test.wantErr)
		})
	}
}

func TestDiscoverRejectsInvalidPayloads(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		status  int
		body    string
		wantErr string
	}{
		{
			name:    "malformed JSON",
			status:  http.StatusOK,
			body:    `{"data":`,
			wantErr: "upstream returned invalid OpenAI model-list JSON",
		},
		{
			name:    "missing data",
			status:  http.StatusOK,
			body:    `{}`,
			wantErr: "upstream returned invalid OpenAI model-list JSON",
		},
		{
			name:    "too many models",
			status:  http.StatusOK,
			body:    modelListJSON(maxModels + 1),
			wantErr: "upstream returned too many models",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
				_, _ = io.WriteString(w, test.body)
			}))
			defer server.Close()

			_, err := newWithTransport(http.DefaultTransport).Discover(context.Background(), Request{
				UpstreamURL: server.URL,
			})
			require.EqualError(t, err, test.wantErr)
		})
	}
}

func modelListJSON(count int) string {
	var body strings.Builder
	body.WriteString(`{"data":[`)
	for i := range count {
		if i > 0 {
			body.WriteByte(',')
		}
		_, _ = fmt.Fprintf(&body, `{"id":"model-%d"}`, i)
	}
	body.WriteString(`]}`)
	return body.String()
}
