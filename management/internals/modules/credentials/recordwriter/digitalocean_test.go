package recordwriter

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// roundTripFunc and helpers in cloudflare_test.go are unexported but in
// the same package, so we can reuse them. We define a small DO-specific
// response helper to mirror cfResp's ergonomics.
func doResp(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

func newDOTestWriter(rt roundTripFunc) *digitalOceanWriter {
	return &digitalOceanWriter{
		authToken:  "test-token",
		httpClient: &http.Client{Transport: rt},
	}
}

func TestDigitalOceanWriter_BuildRequiresAuthToken(t *testing.T) {
	if _, err := buildDigitalOceanWriter(map[string]string{}); err == nil {
		t.Fatal("expected error for missing auth_token")
	}
	if _, err := buildDigitalOceanWriter(map[string]string{"auth_token": "x"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDigitalOceanWriter_RegistersAtInit(t *testing.T) {
	if _, err := BuildRecordWriter("digitalocean", map[string]string{"auth_token": "x"}); err != nil {
		t.Fatalf("expected digitalocean to be registered: %v", err)
	}
}

func TestDigitalOceanWriter_WriteCNAME_HappyPath(t *testing.T) {
	calls := []string{}
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls = append(calls, req.Method+" "+req.URL.Path)
		switch {
		// Zone lookups: "app.example.com" not found, "example.com" found.
		case req.Method == http.MethodGet && req.URL.Path == "/v2/domains/app.example.com":
			return doResp(404, `{"id":"not_found","message":"The resource you were accessing could not be found."}`), nil
		case req.Method == http.MethodGet && req.URL.Path == "/v2/domains/example.com":
			return doResp(200, `{"domain":{"name":"example.com","ttl":1800}}`), nil
		// Record list returns empty.
		case req.Method == http.MethodGet && req.URL.Path == "/v2/domains/example.com/records":
			return doResp(200, `{"domain_records":[]}`), nil
		// Create succeeds.
		case req.Method == http.MethodPost && req.URL.Path == "/v2/domains/example.com/records":
			return doResp(201, `{"domain_record":{"id":12345,"type":"CNAME","name":"*.app","data":"us-east.proxy.netbird.io.","ttl":300}}`), nil
		}
		t.Errorf("unexpected request: %s %s", req.Method, req.URL.Path)
		return doResp(500, ""), nil
	})

	w := newDOTestWriter(rt)
	if err := w.WriteCNAME(context.Background(), "*.app.example.com", "us-east.proxy.netbird.io", 300); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(calls) < 4 {
		t.Fatalf("expected at least 4 API calls (zone miss, zone hit, record list, create), got %d: %v", len(calls), calls)
	}
}

func TestDigitalOceanWriter_WriteCNAME_IdempotentMatch(t *testing.T) {
	wrote := false
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodGet && req.URL.Path == "/v2/domains/app.example.com":
			return doResp(404, `{"id":"not_found","message":"x"}`), nil
		case req.Method == http.MethodGet && req.URL.Path == "/v2/domains/example.com":
			return doResp(200, `{"domain":{"name":"example.com"}}`), nil
		case req.Method == http.MethodGet && req.URL.Path == "/v2/domains/example.com/records":
			// Existing record matches — note DO appends trailing dot.
			return doResp(200, `{"domain_records":[{"id":12345,"type":"CNAME","name":"*.app","data":"us-east.proxy.netbird.io.","ttl":300}]}`), nil
		case req.Method == http.MethodPost:
			wrote = true
			return doResp(201, `{}`), nil
		}
		return doResp(404, `{}`), nil
	})

	w := newDOTestWriter(rt)
	if err := w.WriteCNAME(context.Background(), "*.app.example.com", "us-east.proxy.netbird.io", 300); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if wrote {
		t.Fatal("idempotent path must not POST when target already matches")
	}
}

func TestDigitalOceanWriter_WriteCNAME_ConflictDifferentTarget(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodGet && req.URL.Path == "/v2/domains/app.example.com":
			return doResp(404, `{}`), nil
		case req.Method == http.MethodGet && req.URL.Path == "/v2/domains/example.com":
			return doResp(200, `{"domain":{"name":"example.com"}}`), nil
		case req.Method == http.MethodGet && req.URL.Path == "/v2/domains/example.com/records":
			return doResp(200, `{"domain_records":[{"id":12345,"type":"CNAME","name":"*.app","data":"someone-else.example.net.","ttl":300}]}`), nil
		}
		return doResp(404, `{}`), nil
	})

	w := newDOTestWriter(rt)
	err := w.WriteCNAME(context.Background(), "*.app.example.com", "us-east.proxy.netbird.io", 300)
	if !errors.Is(err, ErrRecordExists) {
		t.Fatalf("expected ErrRecordExists, got %v", err)
	}
}

func TestDigitalOceanWriter_WriteCNAME_ZoneNotFound(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		// Every zone GET returns 404.
		return doResp(404, `{"id":"not_found","message":"The resource you were accessing could not be found."}`), nil
	})

	w := newDOTestWriter(rt)
	err := w.WriteCNAME(context.Background(), "*.app.example.com", "x.netbird.io", 300)
	if !errors.Is(err, ErrZoneNotFound) {
		t.Fatalf("expected ErrZoneNotFound, got %v", err)
	}
}

func TestDigitalOceanWriter_WriteCNAME_AuthFailure(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return doResp(403, `{"id":"forbidden","message":"You do not have access for the attempted action."}`), nil
	})

	w := newDOTestWriter(rt)
	err := w.WriteCNAME(context.Background(), "*.app.example.com", "x.netbird.io", 300)
	if !errors.Is(err, ErrInsufficientScope) {
		t.Fatalf("expected ErrInsufficientScope, got %v", err)
	}
}

func TestDigitalOceanWriter_DeleteCNAME_IdempotentMissingRecord(t *testing.T) {
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodGet && req.URL.Path == "/v2/domains/app.example.com":
			return doResp(404, `{}`), nil
		case req.Method == http.MethodGet && req.URL.Path == "/v2/domains/example.com":
			return doResp(200, `{"domain":{"name":"example.com"}}`), nil
		case req.Method == http.MethodGet && req.URL.Path == "/v2/domains/example.com/records":
			return doResp(200, `{"domain_records":[]}`), nil
		case req.Method == http.MethodDelete:
			t.Errorf("delete request should not be issued when record absent: %s", req.URL.Path)
			return doResp(500, ""), nil
		}
		t.Errorf("unexpected request: %s %s", req.Method, req.URL.Path)
		return doResp(500, ""), nil
	})

	w := newDOTestWriter(rt)
	if err := w.DeleteCNAME(context.Background(), "*.app.example.com"); err != nil {
		t.Fatalf("delete on missing record should be no-op, got %v", err)
	}
}

func TestDigitalOceanWriter_WriteCNAME_NameRelativization(t *testing.T) {
	// Capture the JSON body sent to the create endpoint and verify the
	// name was relativized correctly: FQDN "*.app.example.com" in zone
	// "example.com" → relative name "*.app".
	var captured doRecord
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodGet && req.URL.Path == "/v2/domains/app.example.com":
			return doResp(404, `{}`), nil
		case req.Method == http.MethodGet && req.URL.Path == "/v2/domains/example.com":
			return doResp(200, `{"domain":{"name":"example.com"}}`), nil
		case req.Method == http.MethodGet && req.URL.Path == "/v2/domains/example.com/records":
			return doResp(200, `{"domain_records":[]}`), nil
		case req.Method == http.MethodPost && req.URL.Path == "/v2/domains/example.com/records":
			body, _ := io.ReadAll(req.Body)
			if err := json.Unmarshal(body, &captured); err != nil {
				t.Fatalf("decode posted body: %v", err)
			}
			return doResp(201, `{"domain_record":{"id":1}}`), nil
		}
		t.Errorf("unexpected request: %s %s", req.Method, req.URL.Path)
		return doResp(500, ""), nil
	})

	w := newDOTestWriter(rt)
	if err := w.WriteCNAME(context.Background(), "*.app.example.com", "us-east.proxy.netbird.io", 300); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if captured.Name != "*.app" {
		t.Fatalf("expected relativized name %q, got %q", "*.app", captured.Name)
	}
	if captured.Type != "CNAME" {
		t.Fatalf("expected type CNAME, got %q", captured.Type)
	}
	if captured.Data != "us-east.proxy.netbird.io" {
		t.Fatalf("expected data %q, got %q", "us-east.proxy.netbird.io", captured.Data)
	}
	if captured.TTL != 300 {
		t.Fatalf("expected ttl 300, got %d", captured.TTL)
	}
}

func TestDigitalOceanWriter_WriteCNAME_NameRelativization_ApexZone(t *testing.T) {
	// FQDN "*.example.com" in zone "example.com" → relative "*".
	var captured doRecord
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodGet && req.URL.Path == "/v2/domains/example.com":
			return doResp(200, `{"domain":{"name":"example.com"}}`), nil
		case req.Method == http.MethodGet && req.URL.Path == "/v2/domains/example.com/records":
			return doResp(200, `{"domain_records":[]}`), nil
		case req.Method == http.MethodPost && req.URL.Path == "/v2/domains/example.com/records":
			body, _ := io.ReadAll(req.Body)
			_ = json.Unmarshal(body, &captured)
			return doResp(201, `{"domain_record":{"id":1}}`), nil
		}
		return doResp(404, `{}`), nil
	})

	w := newDOTestWriter(rt)
	if err := w.WriteCNAME(context.Background(), "*.example.com", "x.netbird.io", 300); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if captured.Name != "*" {
		t.Fatalf("expected relativized name %q, got %q", "*", captured.Name)
	}
}

func TestDigitalOceanWriter_RelativizeName(t *testing.T) {
	cases := []struct {
		fqdn, zone, want string
	}{
		{"*.app.example.com", "example.com", "*.app"},
		{"*.app.example.com", "app.example.com", "*"},
		{"app.example.com", "example.com", "app"},
		{"example.com", "example.com", "@"},
		{"*.example.com", "example.com", "*"},
	}
	for _, c := range cases {
		got := relativizeName(c.fqdn, c.zone)
		if got != c.want {
			t.Errorf("relativizeName(%q, %q) = %q, want %q", c.fqdn, c.zone, got, c.want)
		}
	}
}
