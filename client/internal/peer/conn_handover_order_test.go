package peer

import (
	"os"
	"strings"
	"testing"
)

// Codex hardening regression: the Relay->ICE/P2P handover in
// conn.go's onICEConnected must call methods in this exact order to
// avoid a window where Relay is paused but WG still points at it
// (1-2 s of dropped packets):
//
//   1. wgProxy.Work()                            (new ICE proxy ready)
//   2. endpointUpdater.ConfigureWGEndpoint(...)  (WG points at new EP)
//   3. wgProxyRelay.RedirectAs(ep)               (drain in-flight relay)
//   4. wgProxyRelay.Pause()                      (stop relay last)
//
// The test below is a static-text check: it reads conn.go and asserts
// the FIRST occurrence of each landmark in onICEConnected appears in
// the expected order. A heavier behavioural test would need fake
// wgProxy/endpointUpdater plumbing; this version catches accidental
// reorders cheaply and points at the exact line numbers if the
// invariant is broken.
func TestConn_HandoverOrder_OnICEConnected(t *testing.T) {
	src, err := os.ReadFile("conn.go")
	if err != nil {
		t.Fatalf("read conn.go: %v", err)
	}
	body := extractFunctionBody(t, string(src), "onICEConnectionIsReady")

	// Landmarks in expected order. Each entry is a substring; the test
	// records the first index where it appears in the function body
	// and asserts the indices increase monotonically.
	landmarks := []string{
		"wgProxy.Work()",
		"endpointUpdater.ConfigureWGEndpoint(",
		"wgProxyRelay.RedirectAs(",
		"wgProxyRelay.Pause()",
	}
	prev := -1
	for _, lm := range landmarks {
		idx := strings.Index(body, lm)
		if idx < 0 {
			t.Errorf("landmark %q missing from onICEConnected — was the handover sequence refactored?", lm)
			continue
		}
		if idx <= prev {
			t.Errorf("landmark %q appears at index %d, must come AFTER previous landmark at %d", lm, idx, prev)
		}
		prev = idx
	}
}

// Codex hardening regression: onICEStateDisconnected must NOT call
// RemoveEndpointAddress in the no-Relay-fallback branch. A stale
// endpoint is less disruptive than a guaranteed no-endpoint gap; the
// next successful path update replaces it.
func TestConn_HandoverOrder_OnICEDisconnected_NoRemoveEndpointAddress(t *testing.T) {
	src, err := os.ReadFile("conn.go")
	if err != nil {
		t.Fatalf("read conn.go: %v", err)
	}
	body := extractFunctionBody(t, string(src), "onICEStateDisconnected")
	// The whole function body must NOT contain a call to
	// RemoveEndpointAddress. (Used to be there in the no-fallback
	// branch; removed in Codex#8b 2026-05-03.)
	if strings.Contains(body, "RemoveEndpointAddress(") {
		t.Error("onICEStateDisconnected must NOT call RemoveEndpointAddress — it creates a no-endpoint gap during ICE flaps; see conn.go comment for rationale")
	}
}

// extractFunctionBody returns the source text between `func name(` and
// the closing brace at column 0 that follows. Crude but sufficient for
// these landmark checks.
func extractFunctionBody(t *testing.T, src, name string) string {
	t.Helper()
	marker := "func (conn *Conn) " + name + "("
	start := strings.Index(src, marker)
	if start < 0 {
		// Plain func form (no receiver) fallback.
		marker = "func " + name + "("
		start = strings.Index(src, marker)
	}
	if start < 0 {
		t.Fatalf("function %q not found in source", name)
	}
	// Find the closing brace at column 0 starting at the next newline
	// after the opening line. Functions in NetBird's style are always
	// indented with leading-tab and the closing } is at column 0.
	rest := src[start:]
	lines := strings.Split(rest, "\n")
	var body strings.Builder
	depth := 0
	openSeen := false
	for _, line := range lines {
		body.WriteString(line)
		body.WriteByte('\n')
		for _, ch := range line {
			if ch == '{' {
				depth++
				openSeen = true
			} else if ch == '}' {
				depth--
				if openSeen && depth == 0 {
					return body.String()
				}
			}
		}
	}
	t.Fatalf("function %q has unbalanced braces", name)
	return ""
}
