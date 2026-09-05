//go:build !js && !ios && !android

package internal

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/client/internal/approval"
	vncserver "github.com/netbirdio/netbird/client/vnc/server"
)

// TestApprovalCause checks that each way the broker can refuse arrives at
// the VNC server as the matching cause. Without this the server sees one
// opaque error and tells every caller it was denied, which reads as "the
// user said no" even when no prompt was ever answered or shown.
func TestApprovalCause(t *testing.T) {
	cases := []struct {
		name string
		in   error
		want error
	}{
		{"denied", approval.ErrDenied, vncserver.ErrApprovalDenied},
		{"timeout", approval.ErrTimeout, vncserver.ErrApprovalTimeout},
		{"no_subscriber", approval.ErrNoSubscriber, vncserver.ErrApprovalUnavailable},
		{"prompt_not_shown", approval.ErrPromptNotShown, vncserver.ErrApprovalUnavailable},
		// Wrapped on the way in: the broker may add context, and the
		// classification must survive it.
		{"wrapped_timeout", fmt.Errorf("request: %w", approval.ErrTimeout), vncserver.ErrApprovalTimeout},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := approvalCause(tc.in)
			assert.ErrorIs(t, got, tc.want, "broker error %v must classify as %v", tc.in, tc.want)
		})
	}
}

// TestApprovalCausePreservesUnavailableDetail: the two unavailable causes
// mean different things to whoever reads the daemon log ("nobody was
// listening" versus "somebody was, and never got it"), so collapsing them
// onto one sentinel must not discard which one occurred.
func TestApprovalCausePreservesUnavailableDetail(t *testing.T) {
	got := approvalCause(approval.ErrPromptNotShown)
	assert.ErrorIs(t, got, vncserver.ErrApprovalUnavailable)
	assert.ErrorIs(t, got, approval.ErrPromptNotShown, "the specific cause must stay readable in the log")
}

// TestApprovalCausePassesThroughUnknown keeps an error the mapping does not
// recognise intact, so the daemon log still shows what actually happened.
// The server rejects it as a denial either way.
func TestApprovalCausePassesThroughUnknown(t *testing.T) {
	for _, err := range []error{context.Canceled, errors.New("something else")} {
		assert.ErrorIs(t, approvalCause(err), err, "unknown cause must pass through unchanged")
	}
}
