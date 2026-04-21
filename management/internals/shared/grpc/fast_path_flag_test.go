package grpc

import (
	"context"
	"testing"
	"time"

	"github.com/eko/gocache/lib/v4/store"
	gocache_store "github.com/eko/gocache/store/go_cache/v4"
	gocache "github.com/patrickmn/go-cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseFastPathFlag(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{"one", "1", true},
		{"true lowercase", "true", true},
		{"true uppercase", "TRUE", true},
		{"true mixed case", "True", true},
		{"true with whitespace", "  true  ", true},
		{"zero", "0", false},
		{"false", "false", false},
		{"empty", "", false},
		{"yes", "yes", false},
		{"garbage", "garbage", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, parseFastPathFlag(tt.value), "parseFastPathFlag(%q)", tt.value)
		})
	}
}

func TestFastPathFlag_EnabledDefaultsFalse(t *testing.T) {
	flag := &FastPathFlag{}
	assert.False(t, flag.Enabled(), "zero value flag should report disabled")
}

func TestFastPathFlag_NilSafeEnabled(t *testing.T) {
	var flag *FastPathFlag
	assert.False(t, flag.Enabled(), "nil flag should report disabled without panicking")
}

func TestFastPathFlag_SetEnabled(t *testing.T) {
	flag := &FastPathFlag{}
	flag.setEnabled(true)
	assert.True(t, flag.Enabled(), "flag should report enabled after setEnabled(true)")
	flag.setEnabled(false)
	assert.False(t, flag.Enabled(), "flag should report disabled after setEnabled(false)")
}

func TestNewFastPathFlag(t *testing.T) {
	assert.True(t, NewFastPathFlag(true).Enabled(), "NewFastPathFlag(true) should report enabled")
	assert.False(t, NewFastPathFlag(false).Enabled(), "NewFastPathFlag(false) should report disabled")
}

func TestRunFastPathFlagRoutine_NilStoreStaysDisabled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	flag := RunFastPathFlagRoutine(ctx, nil, 50*time.Millisecond, "peerSyncFastPath")
	require.NotNil(t, flag, "RunFastPathFlagRoutine should always return a non-nil flag")
	assert.False(t, flag.Enabled(), "flag should stay disabled when no cache store is provided")

	time.Sleep(150 * time.Millisecond)
	assert.False(t, flag.Enabled(), "flag should remain disabled after wait when no cache store is provided")
}

func TestRunFastPathFlagRoutine_ReadsFlagFromStore(t *testing.T) {
	cacheStore := newFastPathTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	flag := RunFastPathFlagRoutine(ctx, cacheStore, 50*time.Millisecond, "peerSyncFastPath")
	require.NotNil(t, flag)
	assert.False(t, flag.Enabled(), "flag should start disabled when the key is missing")

	require.NoError(t, cacheStore.Set(ctx, "peerSyncFastPath", "1"), "seed flag=1 into shared store")
	assert.Eventually(t, flag.Enabled, 2*time.Second, 25*time.Millisecond, "flag should flip enabled after the key is set to 1")

	require.NoError(t, cacheStore.Set(ctx, "peerSyncFastPath", "0"), "override flag=0 into shared store")
	assert.Eventually(t, func() bool {
		return !flag.Enabled()
	}, 2*time.Second, 25*time.Millisecond, "flag should flip disabled after the key is set to 0")

	require.NoError(t, cacheStore.Delete(ctx, "peerSyncFastPath"), "remove flag key")
	assert.Eventually(t, func() bool {
		return !flag.Enabled()
	}, 2*time.Second, 25*time.Millisecond, "flag should stay disabled after the key is deleted")

	require.NoError(t, cacheStore.Set(ctx, "peerSyncFastPath", "true"), "enable via string true")
	assert.Eventually(t, flag.Enabled, 2*time.Second, 25*time.Millisecond, "flag should accept \"true\" as enabled")
}

func TestRunFastPathFlagRoutine_MissingKeyKeepsDisabled(t *testing.T) {
	cacheStore := newFastPathTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	flag := RunFastPathFlagRoutine(ctx, cacheStore, 50*time.Millisecond, "peerSyncFastPathAbsent")
	require.NotNil(t, flag)

	time.Sleep(200 * time.Millisecond)
	assert.False(t, flag.Enabled(), "flag should stay disabled when the key is missing from the store")
}

func TestRunFastPathFlagRoutine_DefaultKeyUsedWhenEmpty(t *testing.T) {
	cacheStore := newFastPathTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	require.NoError(t, cacheStore.Set(ctx, DefaultFastPathFlagKey, "1"), "seed default key")

	flag := RunFastPathFlagRoutine(ctx, cacheStore, 50*time.Millisecond, "")
	require.NotNil(t, flag)

	assert.Eventually(t, flag.Enabled, 2*time.Second, 25*time.Millisecond, "empty flagKey should fall back to DefaultFastPathFlagKey")
}

func newFastPathTestStore(t *testing.T) store.StoreInterface {
	t.Helper()
	return gocache_store.NewGoCache(gocache.New(5*time.Minute, 10*time.Minute))
}
