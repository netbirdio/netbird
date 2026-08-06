package cache_test

import (
	"context"
	"testing"
	"time"

	"github.com/netbirdio/netbird/management/server/cache"
)

func TestMemoryStore(t *testing.T) {
	memStore, err := cache.NewStore(context.Background(), 100*time.Millisecond, 300*time.Millisecond, 100)
	if err != nil {
		t.Fatalf("couldn't create memory store: %s", err)
	}
	ctx := context.Background()
	key, value := "testing", "tested"
	err = memStore.Set(ctx, key, value)
	if err != nil {
		t.Errorf("couldn't set testing data: %s", err)
	}
	result, err := memStore.Get(ctx, key)
	if err != nil {
		t.Errorf("couldn't get testing data: %s", err)
	}
	if value != result.(string) {
		t.Errorf("value returned doesn't match testing data, got %s, expected %s", result, value)
	}
	created, err := memStore.SetNX(ctx, "atomic", value, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("couldn't atomically set testing data: %s", err)
	}
	if !created {
		t.Fatal("first atomic set should create the entry")
	}
	created, err = memStore.SetNX(ctx, "atomic", value, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("couldn't atomically check testing data: %s", err)
	}
	if created {
		t.Fatal("second atomic set should not replace the entry")
	}
	// test expiration
	time.Sleep(300 * time.Millisecond)
	_, err = memStore.Get(ctx, key)
	if err == nil {
		t.Error("value should not be found")
	}
}

func TestMemoryStoreGetDel(t *testing.T) {
	ctx := context.Background()
	newStore := func(t *testing.T) cache.Store {
		t.Helper()
		memStore, err := cache.NewStore(ctx, time.Minute, time.Minute, 100)
		if err != nil {
			t.Fatalf("couldn't create memory store: %s", err)
		}
		return memStore
	}

	const (
		key   = "consume"
		value = "verifier"
	)

	t.Run("exactly one concurrent caller consumes the key", func(t *testing.T) {
		memStore := newStore(t)
		if err := memStore.Set(ctx, key, value); err != nil {
			t.Fatalf("couldn't set testing data: %s", err)
		}

		assertGetDelConsumedOnce(ctx, t, []cache.Store{memStore}, key, value)
		assertGetDelMisses(ctx, t, memStore, key)
	})

	t.Run("missing key is not an error", func(t *testing.T) {
		assertGetDelMisses(ctx, t, newStore(t), "never-set")
	})

	t.Run("expired key is not found", func(t *testing.T) {
		memStore := newStore(t)
		if _, err := memStore.SetNX(ctx, key, value, 50*time.Millisecond); err != nil {
			t.Fatalf("couldn't set testing data: %s", err)
		}

		time.Sleep(100 * time.Millisecond)
		assertGetDelMisses(ctx, t, memStore, key)
	})
}
