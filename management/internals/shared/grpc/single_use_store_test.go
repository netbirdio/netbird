package grpc

import (
	"context"
	"testing"
	"time"
)

func TestSingleUseStoreLoadAndDelete(t *testing.T) {
	const (
		state    = "state"
		verifier = "verifier"
		attempts = 64
	)

	t.Run("exactly one concurrent caller consumes the verifier", func(t *testing.T) {
		store := NewSingleUseStore(context.Background(), testCacheStore(t))
		if err := store.Store(state, verifier, time.Minute); err != nil {
			t.Fatalf("couldn't store PKCE verifier: %s", err)
		}

		start := make(chan struct{})
		type result struct {
			verifier string
			found    bool
		}
		results := make(chan result, attempts)
		for range attempts {
			go func() {
				<-start
				verifier, found := store.LoadAndDelete(state)
				results <- result{verifier: verifier, found: found}
			}()
		}
		close(start)

		winners := 0
		for range attempts {
			result := <-results
			if result.found {
				winners++
				if result.verifier != verifier {
					t.Fatalf("unexpected verifier: got %q, expected %q", result.verifier, verifier)
				}
			}
		}
		if winners != 1 {
			t.Fatalf("expected exactly one PKCE verifier consumer, got %d", winners)
		}
	})

	t.Run("replayed state is rejected", func(t *testing.T) {
		store := NewSingleUseStore(context.Background(), testCacheStore(t))
		if err := store.Store(state, verifier, time.Minute); err != nil {
			t.Fatalf("couldn't store PKCE verifier: %s", err)
		}

		if got, found := store.LoadAndDelete(state); !found || got != verifier {
			t.Fatalf("first load should return the verifier, got %q, found %t", got, found)
		}
		if got, found := store.LoadAndDelete(state); found {
			t.Fatalf("replayed state should not resolve, got %q", got)
		}
	})

	t.Run("unknown state is rejected", func(t *testing.T) {
		store := NewSingleUseStore(context.Background(), testCacheStore(t))

		if got, found := store.LoadAndDelete("never-stored"); found {
			t.Fatalf("unknown state should not resolve, got %q", got)
		}
	})

	t.Run("expired verifier is rejected", func(t *testing.T) {
		store := NewSingleUseStore(context.Background(), testCacheStore(t))
		if err := store.Store(state, verifier, 50*time.Millisecond); err != nil {
			t.Fatalf("couldn't store PKCE verifier: %s", err)
		}

		time.Sleep(100 * time.Millisecond)
		if got, found := store.LoadAndDelete(state); found {
			t.Fatalf("expired verifier should not resolve, got %q", got)
		}
	})
}

func TestSingleUseStore_GenerateAndConsumeOnce(t *testing.T) {
	s := NewSingleUseStore(context.Background(), testCacheStore(t))

	key, err := s.Generate("the-value", time.Minute)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if key == "" || key == "the-value" {
		t.Fatalf("unexpected key %q", key)
	}

	value, found := s.LoadAndDelete(key)
	if !found || value != "the-value" {
		t.Fatalf("expected to load the stored value, got %q found=%v", value, found)
	}

	if _, found := s.LoadAndDelete(key); found {
		t.Fatal("value must be consumed on first LoadAndDelete")
	}
}

func TestSingleUseStore_GenerateUniqueKeys(t *testing.T) {
	s := NewSingleUseStore(context.Background(), testCacheStore(t))
	a, err := s.Generate("v", time.Minute)
	if err != nil {
		t.Fatalf("generate a: %v", err)
	}
	b, err := s.Generate("v", time.Minute)
	if err != nil {
		t.Fatalf("generate b: %v", err)
	}
	if a == b {
		t.Fatal("generated keys must be distinct")
	}
}
