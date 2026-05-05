package proxy

import (
	"context"
	"io"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/proxy/internal/health"
	"github.com/netbirdio/netbird/proxy/internal/types"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// collectStaleIDs mirrors the stale-detection logic in reconcileSnapshot
// so we can verify it without triggering removeMapping (which requires full
// server wiring). This keeps the test focused on the detection algorithm.
func collectStaleIDs(lastMappings map[types.ServiceID]*proto.ProxyMapping, snapshotIDs map[types.ServiceID]struct{}) []types.ServiceID {
	var stale []types.ServiceID
	for svcID := range lastMappings {
		if _, ok := snapshotIDs[svcID]; !ok {
			stale = append(stale, svcID)
		}
	}
	return stale
}

// TestStaleDetection_PartialOverlap verifies that only services absent from
// the snapshot are flagged as stale.
func TestStaleDetection_PartialOverlap(t *testing.T) {
	local := map[types.ServiceID]*proto.ProxyMapping{
		"svc-1":       {Id: "svc-1"},
		"svc-2":       {Id: "svc-2"},
		"svc-stale-a": {Id: "svc-stale-a"},
		"svc-stale-b": {Id: "svc-stale-b"},
	}
	snapshot := map[types.ServiceID]struct{}{
		"svc-1": {},
		"svc-2": {},
		"svc-3": {}, // new service, not in local
	}

	stale := collectStaleIDs(local, snapshot)
	assert.Len(t, stale, 2)
	staleSet := make(map[types.ServiceID]struct{})
	for _, id := range stale {
		staleSet[id] = struct{}{}
	}
	assert.Contains(t, staleSet, types.ServiceID("svc-stale-a"))
	assert.Contains(t, staleSet, types.ServiceID("svc-stale-b"))
}

// TestStaleDetection_AllStale verifies an empty snapshot flags everything.
func TestStaleDetection_AllStale(t *testing.T) {
	local := map[types.ServiceID]*proto.ProxyMapping{
		"svc-1": {Id: "svc-1"},
		"svc-2": {Id: "svc-2"},
	}
	stale := collectStaleIDs(local, map[types.ServiceID]struct{}{})
	assert.Len(t, stale, 2)
}

// TestStaleDetection_NoneStale verifies full overlap produces no stale entries.
func TestStaleDetection_NoneStale(t *testing.T) {
	local := map[types.ServiceID]*proto.ProxyMapping{
		"svc-1": {Id: "svc-1"},
		"svc-2": {Id: "svc-2"},
	}
	snapshot := map[types.ServiceID]struct{}{
		"svc-1": {},
		"svc-2": {},
	}
	stale := collectStaleIDs(local, snapshot)
	assert.Empty(t, stale)
}

// TestStaleDetection_EmptyLocal verifies no stale entries when local is empty.
func TestStaleDetection_EmptyLocal(t *testing.T) {
	stale := collectStaleIDs(
		map[types.ServiceID]*proto.ProxyMapping{},
		map[types.ServiceID]struct{}{"svc-1": {}},
	)
	assert.Empty(t, stale)
}

// TestReconcileSnapshot_NoStale verifies reconciliation is a no-op when all
// local mappings are present in the snapshot (removeMapping is never called).
func TestReconcileSnapshot_NoStale(t *testing.T) {
	s := &Server{
		Logger:       log.StandardLogger(),
		lastMappings: make(map[types.ServiceID]*proto.ProxyMapping),
	}
	s.lastMappings["svc-1"] = &proto.ProxyMapping{Id: "svc-1"}
	s.lastMappings["svc-2"] = &proto.ProxyMapping{Id: "svc-2"}

	snapshotIDs := map[types.ServiceID]struct{}{
		"svc-1": {},
		"svc-2": {},
	}
	// This should not panic — no stale entries means removeMapping is never called.
	s.reconcileSnapshot(context.Background(), snapshotIDs)

	assert.Len(t, s.lastMappings, 2, "no mappings should be removed when all are in snapshot")
}

// TestReconcileSnapshot_EmptyLocal verifies reconciliation is a no-op with
// no local mappings.
func TestReconcileSnapshot_EmptyLocal(t *testing.T) {
	s := &Server{
		Logger:       log.StandardLogger(),
		lastMappings: make(map[types.ServiceID]*proto.ProxyMapping),
	}
	s.reconcileSnapshot(context.Background(), map[types.ServiceID]struct{}{"svc-1": {}})
	assert.Empty(t, s.lastMappings)
}

// --- handleMappingStream tests for batched snapshot ID accumulation ---

// TestHandleMappingStream_BatchedSnapshotSyncComplete verifies that sync is
// marked done only after the final InitialSyncComplete message, even when
// the snapshot arrives in multiple batches.
func TestHandleMappingStream_BatchedSnapshotSyncComplete(t *testing.T) {
	checker := health.NewChecker(nil, nil)
	s := &Server{
		Logger:        log.StandardLogger(),
		healthChecker: checker,
		routerReady:   closedChan(),
		lastMappings:  make(map[types.ServiceID]*proto.ProxyMapping),
	}

	stream := &mockMappingStream{
		messages: []*proto.GetMappingUpdateResponse{
			{},                          // batch 1: no sync-complete
			{},                          // batch 2: no sync-complete
			{InitialSyncComplete: true}, // batch 3: sync done
		},
	}

	syncDone := false
	err := s.handleMappingStream(context.Background(), stream, &syncDone)
	assert.NoError(t, err)
	assert.True(t, syncDone, "sync should be marked done after final batch")
}

// TestHandleMappingStream_PostSyncDoesNotReconcile verifies that messages
// arriving after InitialSyncComplete do not trigger a second reconciliation.
func TestHandleMappingStream_PostSyncDoesNotReconcile(t *testing.T) {
	s := &Server{
		Logger:       log.StandardLogger(),
		routerReady:  closedChan(),
		lastMappings: make(map[types.ServiceID]*proto.ProxyMapping),
	}

	// Simulate state left over from a previous sync.
	s.lastMappings["svc-1"] = &proto.ProxyMapping{Id: "svc-1", AccountId: "acct-1"}
	s.lastMappings["svc-2"] = &proto.ProxyMapping{Id: "svc-2", AccountId: "acct-1"}

	stream := &mockMappingStream{
		messages: []*proto.GetMappingUpdateResponse{
			{}, // post-sync empty message — must not reconcile
		},
	}

	syncDone := true // sync already completed in a previous stream
	err := s.handleMappingStream(context.Background(), stream, &syncDone)
	require.NoError(t, err)

	assert.Len(t, s.lastMappings, 2,
		"post-sync messages must not trigger reconciliation — all entries should survive")
}

// TestHandleMappingStream_ImmediateEOF_NoReconciliation verifies that if the
// stream closes before sync completes, no reconciliation occurs.
func TestHandleMappingStream_ImmediateEOF_NoReconciliation(t *testing.T) {
	s := &Server{
		Logger:       log.StandardLogger(),
		routerReady:  closedChan(),
		lastMappings: make(map[types.ServiceID]*proto.ProxyMapping),
	}

	s.lastMappings["svc-stale"] = &proto.ProxyMapping{Id: "svc-stale", AccountId: "acct-1"}

	stream := &mockMappingStream{} // no messages → immediate EOF

	syncDone := false
	err := s.handleMappingStream(context.Background(), stream, &syncDone)
	assert.NoError(t, err)
	assert.False(t, syncDone, "sync should not be marked done on immediate EOF")

	_, hasStale := s.lastMappings["svc-stale"]
	assert.True(t, hasStale, "stale mapping should remain when sync never completed")
}

// mockErrRecvStream returns an error on the second Recv to verify
// handleMappingStream returns without completing sync.
type mockErrRecvStream struct {
	mockMappingStream
	calls int
}

func (m *mockErrRecvStream) Recv() (*proto.GetMappingUpdateResponse, error) {
	m.calls++
	if m.calls == 1 {
		return &proto.GetMappingUpdateResponse{}, nil
	}
	return nil, io.ErrUnexpectedEOF
}

func TestHandleMappingStream_ErrorMidSync_NoReconciliation(t *testing.T) {
	s := &Server{
		Logger:       log.StandardLogger(),
		routerReady:  closedChan(),
		lastMappings: make(map[types.ServiceID]*proto.ProxyMapping),
	}

	s.lastMappings["svc-stale"] = &proto.ProxyMapping{Id: "svc-stale", AccountId: "acct-1"}

	syncDone := false
	err := s.handleMappingStream(context.Background(), &mockErrRecvStream{}, &syncDone)
	assert.Error(t, err)
	assert.False(t, syncDone)

	_, hasStale := s.lastMappings["svc-stale"]
	assert.True(t, hasStale, "stale mapping should remain when sync was interrupted by error")
}
