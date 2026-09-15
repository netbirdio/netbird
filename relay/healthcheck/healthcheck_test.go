package healthcheck

import (
	"context"
	"net/http/httptest"
	"testing"
)

// TestNewServer_NilServiceChecker verifies that a healthcheck server can be
// constructed without a ServiceChecker, which is the case when the relay
// component is not enabled on this instance.
func TestNewServer_NilServiceChecker(t *testing.T) {
	srv, err := NewServer(Config{ListenAddress: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if srv == nil {
		t.Fatal("expected a non-nil server")
	}
}

// TestGetHealthStatus_NilServiceChecker verifies that getHealthStatus reports
// a healthy status without calling into a nil ServiceChecker, guarding
// against the panic this previously caused when the relay was disabled.
func TestGetHealthStatus_NilServiceChecker(t *testing.T) {
	srv, err := NewServer(Config{ListenAddress: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	status, healthy := srv.getHealthStatus(context.Background())
	if !healthy {
		t.Error("expected healthy=true when relay is not applicable, got false")
	}
	if status.Status != statusHealthy {
		t.Errorf("expected status %q, got %q", statusHealthy, status.Status)
	}
	if len(status.Listeners) != 0 {
		t.Errorf("expected no listeners when relay is not applicable, got %v", status.Listeners)
	}
}

// TestHandleHealthcheck_NilServiceChecker exercises the full HTTP handler to
// confirm a request against a healthcheck server without a relay configured
// returns 200 instead of panicking, reproducing the scenario from the bug
// report (relay.enabled=false).
func TestHandleHealthcheck_NilServiceChecker(t *testing.T) {
	srv, err := NewServer(Config{ListenAddress: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest("GET", path, nil)
	w := httptest.NewRecorder()

	srv.handleHealthcheck(w, req)

	if w.Code != 200 {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}
