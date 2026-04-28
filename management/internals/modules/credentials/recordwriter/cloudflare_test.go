package recordwriter

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// roundTripFunc lets tests inject canned responses without standing up a
// real HTTP server. Mirrors httptest.Server semantics but stays in-process.
type roundTripFunc func(req *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func cfResp(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

func newTestWriter(rt roundTripFunc) *cloudflareWriter {
	return &cloudflareWriter{
		authToken:  "test-token",
		httpClient: &http.Client{Transport: rt},
	}
}

func TestCloudflareWriter_BuildRequiresAuthToken(t *testing.T) {
	if _, err := buildCloudflareWriter(map[string]string{}); err == nil {
		t.Fatal("expected error for missing auth_token")
	}
	if _, err := buildCloudflareWriter(map[string]string{"auth_token": "x"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Legacy fallback for plain-string Cloudflare credentials.
	if _, err := buildCloudflareWriter(map[string]string{"_legacy": "x"}); err != nil {
		t.Fatalf("legacy fallback should succeed: %v", err)
	}
}

func TestCloudflareWriter_RegistersAtInit(t *testing.T) {
	if _, err := BuildRecordWriter("cloudflare", map[string]string{"auth_token": "x"}); err != nil {
		t.Fatalf("expected cloudflare to be registered: %v", err)
	}
	if _, err := BuildRecordWriter("nonsense", map[string]string{}); err == nil {
		t.Fatal("expected unknown provider to error")
	}
}

func TestCloudflareWriter_WriteCNAME_HappyPath(t *testing.T) {
	calls := []string{}
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls = append(calls, req.Method+" "+req.URL.Path+"?"+req.URL.RawQuery)
		switch {
		case req.Method == http.MethodGet && req.URL.Path == "/client/v4/zones":
			// Zone lookup succeeds for the longest candidate.
			name, _ := url.QueryUnescape(req.URL.Query().Get("name"))
			if name == "example.com" {
				return cfResp(200, `{"success":true,"errors":[],"result":[{"id":"zone1","name":"example.com"}]}`), nil
			}
			return cfResp(200, `{"success":true,"errors":[],"result":[]}`), nil
		case req.Method == http.MethodGet && strings.HasSuffix(req.URL.Path, "/dns_records"):
			// No existing record.
			return cfResp(200, `{"success":true,"errors":[],"result":[]}`), nil
		case req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/dns_records"):
			return cfResp(200, `{"success":true,"errors":[],"result":{"id":"rec1"}}`), nil
		}
		return cfResp(404, `{"success":false,"errors":[]}`), nil
	})

	w := newTestWriter(rt)
	if err := w.WriteCNAME(context.Background(), "*.app.example.com", "us-east.proxy.netbird.io", 300); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(calls) < 3 {
		t.Fatalf("expected at least 3 API calls (zone lookup, record list, create), got %d: %v", len(calls), calls)
	}
}

func TestCloudflareWriter_WriteCNAME_IdempotentMatch(t *testing.T) {
	wrote := false
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodGet && req.URL.Path == "/client/v4/zones":
			return cfResp(200, `{"success":true,"errors":[],"result":[{"id":"zone1","name":"example.com"}]}`), nil
		case req.Method == http.MethodGet && strings.HasSuffix(req.URL.Path, "/dns_records"):
			// Existing record matches target.
			return cfResp(200, `{"success":true,"errors":[],"result":[{"id":"rec1","type":"CNAME","name":"*.app.example.com","content":"us-east.proxy.netbird.io"}]}`), nil
		case req.Method == http.MethodPost:
			wrote = true
			return cfResp(200, `{"success":true}`), nil
		}
		return cfResp(404, `{"success":false}`), nil
	})

	w := newTestWriter(rt)
	if err := w.WriteCNAME(context.Background(), "*.app.example.com", "us-east.proxy.netbird.io", 300); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if wrote {
		t.Fatal("idempotent path must not POST when target already matches")
	}
}

func TestCloudflareWriter_WriteCNAME_ConflictDifferentTarget(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.URL.Path == "/client/v4/zones":
			return cfResp(200, `{"success":true,"errors":[],"result":[{"id":"zone1","name":"example.com"}]}`), nil
		case strings.HasSuffix(req.URL.Path, "/dns_records") && req.Method == http.MethodGet:
			return cfResp(200, `{"success":true,"errors":[],"result":[{"id":"rec1","type":"CNAME","name":"*.app.example.com","content":"someone-else.example.net"}]}`), nil
		}
		return cfResp(404, `{"success":false}`), nil
	})

	w := newTestWriter(rt)
	err := w.WriteCNAME(context.Background(), "*.app.example.com", "us-east.proxy.netbird.io", 300)
	if !errors.Is(err, ErrRecordExists) {
		t.Fatalf("expected ErrRecordExists, got %v", err)
	}
}

func TestCloudflareWriter_WriteCNAME_ZoneNotFound(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		// All zone lookups return empty.
		return cfResp(200, `{"success":true,"errors":[],"result":[]}`), nil
	})

	w := newTestWriter(rt)
	err := w.WriteCNAME(context.Background(), "*.app.example.com", "x.netbird.io", 300)
	if !errors.Is(err, ErrZoneNotFound) {
		t.Fatalf("expected ErrZoneNotFound, got %v", err)
	}
}

func TestCloudflareWriter_WriteCNAME_AuthFailure(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return cfResp(403, `{"success":false,"errors":[{"code":9109,"message":"Unauthorized"}]}`), nil
	})

	w := newTestWriter(rt)
	err := w.WriteCNAME(context.Background(), "*.app.example.com", "x.netbird.io", 300)
	if !errors.Is(err, ErrInsufficientScope) {
		t.Fatalf("expected ErrInsufficientScope, got %v", err)
	}
}

func TestCloudflareWriter_WriteCNAME_LongestApexWins(t *testing.T) {
	// User has both example.com.au and example.com registered.
	// FQDN *.api.example.com must match example.com (the rightful zone),
	// not example.com.au (which doesn't end with .example.com but happens
	// to share a prefix in candidate generation if implemented poorly).
	zoneLookups := []string{}
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/client/v4/zones" {
			name, _ := url.QueryUnescape(req.URL.Query().Get("name"))
			zoneLookups = append(zoneLookups, name)
			if name == "example.com" {
				return cfResp(200, `{"success":true,"errors":[],"result":[{"id":"zone1","name":"example.com"}]}`), nil
			}
			return cfResp(200, `{"success":true,"errors":[],"result":[]}`), nil
		}
		if strings.HasSuffix(req.URL.Path, "/dns_records") {
			if req.Method == http.MethodGet {
				return cfResp(200, `{"success":true,"errors":[],"result":[]}`), nil
			}
			return cfResp(200, `{"success":true,"errors":[],"result":{"id":"rec1"}}`), nil
		}
		return cfResp(404, `{"success":false}`), nil
	})

	w := newTestWriter(rt)
	if err := w.WriteCNAME(context.Background(), "*.api.example.com", "x.netbird.io", 300); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Order matters: we should query api.example.com first, then example.com.
	if len(zoneLookups) < 2 || zoneLookups[0] != "api.example.com" || zoneLookups[1] != "example.com" {
		t.Fatalf("expected longest-first lookups [api.example.com example.com], got %v", zoneLookups)
	}
}

func TestCloudflareWriter_DeleteCNAME_Idempotent(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.URL.Path == "/client/v4/zones":
			return cfResp(200, `{"success":true,"errors":[],"result":[{"id":"zone1","name":"example.com"}]}`), nil
		case strings.HasSuffix(req.URL.Path, "/dns_records") && req.Method == http.MethodGet:
			return cfResp(200, `{"success":true,"errors":[],"result":[]}`), nil
		}
		t.Errorf("unexpected request: %s %s", req.Method, req.URL.Path)
		return cfResp(500, ""), nil
	})

	w := newTestWriter(rt)
	if err := w.DeleteCNAME(context.Background(), "*.app.example.com"); err != nil {
		t.Fatalf("delete on missing record should be no-op, got %v", err)
	}
}

func TestApexCandidates(t *testing.T) {
	cases := []struct {
		fqdn string
		want []string
	}{
		{"*.app.example.com", []string{"app.example.com", "example.com"}},
		{"app.example.com", []string{"app.example.com", "example.com"}},
		{"example.com", []string{"example.com"}},
		{"*.example.co.uk", []string{"example.co.uk"}},
		{"*.deeply.nested.sub.example.com", []string{"deeply.nested.sub.example.com", "nested.sub.example.com", "sub.example.com", "example.com"}},
	}
	for _, c := range cases {
		got := apexCandidates(c.fqdn)
		if len(got) != len(c.want) {
			t.Errorf("apexCandidates(%q): got %v want %v", c.fqdn, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("apexCandidates(%q): position %d got %q want %q", c.fqdn, i, got[i], c.want[i])
			}
		}
	}
}
