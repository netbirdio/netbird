package middleware

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const revisionTestMiddlewareID = "revision_test"

type revisionTestFactory struct {
	builds atomic.Int64
}

func (f *revisionTestFactory) ID() string {
	return revisionTestMiddlewareID
}

func (f *revisionTestFactory) New(_ []byte) (Middleware, error) {
	f.builds.Add(1)
	return revisionTestMiddleware{}, nil
}

type revisionTestMiddleware struct{}

func (revisionTestMiddleware) ID() string                     { return revisionTestMiddlewareID }
func (revisionTestMiddleware) Version() string                { return "test" }
func (revisionTestMiddleware) Slot() Slot                     { return SlotOnRequest }
func (revisionTestMiddleware) AcceptedContentTypes() []string { return nil }
func (revisionTestMiddleware) MetadataKeys() []string         { return nil }
func (revisionTestMiddleware) MutationsSupported() bool       { return false }
func (revisionTestMiddleware) Invoke(context.Context, *Input) (*Output, error) {
	return &Output{Decision: DecisionAllow}, nil
}
func (revisionTestMiddleware) Close() error { return nil }

func newRevisionTestManager(t *testing.T) (*Manager, *revisionTestFactory) {
	t.Helper()
	factory := &revisionTestFactory{}
	registry := NewRegistry()
	require.NoError(t, registry.Register(factory))
	manager := NewManager(1, nil, nil)
	manager.SetResolver(NewResolver(registry))
	return manager, factory
}

func revisionTestBinding(serviceID, pathID string) PathTargetBinding {
	return PathTargetBinding{
		ServiceID: serviceID,
		PathID:    pathID,
		Specs: []Spec{{
			ID:      revisionTestMiddlewareID,
			Slot:    SlotOnRequest,
			Enabled: true,
		}},
	}
}

func TestManagerRebuildSnapshotRevisionLookup(t *testing.T) {
	manager, _ := newRevisionTestManager(t)
	binding := revisionTestBinding("service", "/")

	revision1, err := manager.RebuildSnapshot("service", []PathTargetBinding{binding})
	require.NoError(t, err)
	require.NotZero(t, revision1)
	chain1, match := manager.ChainForRevision("service", "/", revision1)
	require.True(t, match)
	require.NotNil(t, chain1)

	revision2, err := manager.RebuildSnapshot("service", []PathTargetBinding{binding})
	require.NoError(t, err)
	assert.NotEqual(t, revision1, revision2)
	chain2, match := manager.ChainForRevision("service", "/", revision2)
	require.True(t, match)
	require.NotNil(t, chain2)
	assert.NotSame(t, chain1, chain2)

	stale, match := manager.ChainForRevision("service", "/", revision1)
	assert.False(t, match)
	assert.Nil(t, stale)
	zero, match := manager.ChainForRevision("service", "/", 0)
	assert.False(t, match)
	assert.Nil(t, zero)
}

func TestManagerRebuildSnapshotTracksChainlessTransitions(t *testing.T) {
	manager, _ := newRevisionTestManager(t)

	chainlessRevision, err := manager.RebuildSnapshot("service", nil)
	require.NoError(t, err)
	chain, match := manager.ChainForRevision("service", "/", chainlessRevision)
	assert.True(t, match)
	assert.Nil(t, chain)

	chainRevision, err := manager.RebuildSnapshot("service", []PathTargetBinding{
		revisionTestBinding("service", "/"),
	})
	require.NoError(t, err)
	_, match = manager.ChainForRevision("service", "/", chainlessRevision)
	assert.False(t, match)
	chain, match = manager.ChainForRevision("service", "/", chainRevision)
	assert.True(t, match)
	assert.NotNil(t, chain)

	chainlessRevision2, err := manager.RebuildSnapshot("service", nil)
	require.NoError(t, err)
	_, match = manager.ChainForRevision("service", "/", chainRevision)
	assert.False(t, match)
	chain, match = manager.ChainForRevision("service", "/", chainlessRevision2)
	assert.True(t, match)
	assert.Nil(t, chain)
}

func TestManagerInvalidateMiddlewarePreservesServiceRevision(t *testing.T) {
	manager, factory := newRevisionTestManager(t)
	revision, err := manager.RebuildSnapshot("service", []PathTargetBinding{
		revisionTestBinding("service", "/"),
	})
	require.NoError(t, err)
	chain1, match := manager.ChainForRevision("service", "/", revision)
	require.True(t, match)
	require.NotNil(t, chain1)

	manager.InvalidateMiddleware(revisionTestMiddlewareID)

	chain2, match := manager.ChainForRevision("service", "/", revision)
	require.True(t, match)
	require.NotNil(t, chain2)
	assert.NotSame(t, chain1, chain2)
	assert.EqualValues(t, 2, factory.builds.Load())
}

func TestManagerInvalidateRemovesRevisionAndReaddDoesNotReuseIt(t *testing.T) {
	manager, _ := newRevisionTestManager(t)
	revision1, err := manager.RebuildSnapshot("service", nil)
	require.NoError(t, err)

	manager.Invalidate("service")
	_, match := manager.ChainForRevision("service", "/", revision1)
	assert.False(t, match)

	revision2, err := manager.RebuildSnapshot("service", nil)
	require.NoError(t, err)
	assert.NotEqual(t, revision1, revision2)
	_, match = manager.ChainForRevision("service", "/", revision2)
	assert.True(t, match)

	manager.InvalidateAll()
	_, match = manager.ChainForRevision("service", "/", revision2)
	assert.False(t, match)

	revision3, err := manager.RebuildSnapshot("service", nil)
	require.NoError(t, err)
	assert.NotEqual(t, revision1, revision3)
	assert.NotEqual(t, revision2, revision3)
}

func TestManagerRebuildSnapshotRejectsMismatchedBindingBeforeMutation(t *testing.T) {
	manager, _ := newRevisionTestManager(t)
	binding := revisionTestBinding("service", "/")
	revision1, err := manager.RebuildSnapshot("service", []PathTargetBinding{binding})
	require.NoError(t, err)
	chain1, match := manager.ChainForRevision("service", "/", revision1)
	require.True(t, match)

	invalid := revisionTestBinding("other-service", "/replacement")
	revision, err := manager.RebuildSnapshot("service", []PathTargetBinding{invalid})
	require.Error(t, err)
	assert.Zero(t, revision)
	chainAfter, match := manager.ChainForRevision("service", "/", revision1)
	assert.True(t, match)
	assert.Same(t, chain1, chainAfter)

	revision2, err := manager.RebuildSnapshot("service", nil)
	require.NoError(t, err)
	assert.Equal(t, revision1+1, revision2, "a rejected rebuild must not consume a revision")
}

func TestManagerConcurrentRebuildSnapshotRevisionsAreUnique(t *testing.T) {
	manager, _ := newRevisionTestManager(t)
	const rebuilds = 64

	start := make(chan struct{})
	revisions := make(chan Revision, rebuilds)
	errors := make(chan error, rebuilds)
	var wg sync.WaitGroup
	for range rebuilds {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			revision, err := manager.RebuildSnapshot("service", nil)
			if err != nil {
				errors <- err
				return
			}
			revisions <- revision
		}()
	}
	close(start)
	wg.Wait()
	close(errors)
	close(revisions)

	for err := range errors {
		require.NoError(t, err)
	}
	seen := make(map[Revision]struct{}, rebuilds)
	for revision := range revisions {
		require.NotZero(t, revision)
		_, duplicate := seen[revision]
		assert.False(t, duplicate, "each successful rebuild must receive a fresh revision")
		seen[revision] = struct{}{}
	}
	require.Len(t, seen, rebuilds)

	matches := 0
	for revision := range seen {
		chain, match := manager.ChainForRevision("service", "/", revision)
		assert.Nil(t, chain)
		if match {
			matches++
		}
	}
	assert.Equal(t, 1, matches, "only the current immutable table revision may match")
}
