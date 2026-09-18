package server

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/routemanager"
	"github.com/netbirdio/netbird/client/proto"
)

func TestSelectionApplied(t *testing.T) {
	tests := map[string]struct {
		err  error
		want bool
	}{
		"nil error":                  {err: nil, want: true},
		"unrelated error":            {err: errors.New("boom"), want: true},
		"wrapped ErrNoRoutesApplied": {err: fmt.Errorf("select routes: %w", routemanager.ErrNoRoutesApplied), want: false},
		"bare ErrNoRoutesApplied":    {err: routemanager.ErrNoRoutesApplied, want: false},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tt.want, selectionApplied(tt.err), "selectionApplied(%v) mismatch", tt.err)
		})
	}
}

func TestPublishSelectionEvent(t *testing.T) {
	s := &Server{statusRecorder: peer.NewRecorder("")}

	s.publishSelectionEvent("Network selection changed", &proto.SelectNetworksRequest{
		NetworkIDs: []string{"lan", "office"},
		Append:     true,
	})

	events := s.statusRecorder.GetEventHistory()
	require.Len(t, events, 1, "exactly one event must be published")

	event := events[0]
	assert.Equal(t, proto.SystemEvent_INFO, event.GetSeverity(), "event severity should be INFO")
	assert.Equal(t, proto.SystemEvent_SYSTEM, event.GetCategory(), "event category should be SYSTEM")
	assert.Equal(t, "Network selection changed", event.GetMessage(), "event message should match the given title")
	assert.Equal(t, "lan, office", event.GetMetadata()["networks"], "networks metadata should join the requested IDs")
	assert.Equal(t, "true", event.GetMetadata()["append"], "append metadata should reflect the request")
	assert.Equal(t, "false", event.GetMetadata()["all"], "all metadata should reflect the request")
}
