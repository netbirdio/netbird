package grpc

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAttestationSessionStore_PutGet(t *testing.T) {
	s := NewAttestationSessionStore()
	sess := AttestationSession{
		ExpectedSecret: []byte("secret"),
		CSRPEM:         "csr-pem",
		WGKey:          "wgkey",
		AccountID:      "acc1",
		ExpiresAt:      time.Now().Add(time.Minute),
	}
	require.NoError(t, s.Put("id1", sess))

	got, ok := s.Get("id1")
	require.True(t, ok, "session must be found")
	assert.Equal(t, []byte("secret"), got.ExpectedSecret)
	assert.Equal(t, "csr-pem", got.CSRPEM)
	assert.Equal(t, "acc1", got.AccountID)
}

func TestAttestationSessionStore_ExpiredReturnsNotFound(t *testing.T) {
	s := NewAttestationSessionStore()
	sess := AttestationSession{ExpiresAt: time.Now().Add(-time.Second)}
	require.NoError(t, s.Put("expired-id", sess))

	_, ok := s.Get("expired-id")
	assert.False(t, ok, "expired session must not be found")
}

func TestAttestationSessionStore_DeleteRemovesSession(t *testing.T) {
	s := NewAttestationSessionStore()
	require.NoError(t, s.Put("del-id", AttestationSession{ExpiresAt: time.Now().Add(time.Minute)}))
	s.Delete("del-id")

	_, ok := s.Get("del-id")
	assert.False(t, ok, "deleted session must not be found")
}

func TestAttestationSessionStore_GetMissingReturnsNotFound(t *testing.T) {
	s := NewAttestationSessionStore()
	_, ok := s.Get("nonexistent")
	assert.False(t, ok)
}

func TestAttestationSessionStore_Cleanup_RemovesExpired(t *testing.T) {
	s := NewAttestationSessionStore()
	require.NoError(t, s.Put("valid", AttestationSession{ExpiresAt: time.Now().Add(time.Hour)}))
	require.NoError(t, s.Put("expired", AttestationSession{ExpiresAt: time.Now().Add(-time.Second)}))

	s.cleanup()

	_, ok := s.Get("valid")
	assert.True(t, ok, "valid session must survive cleanup")
	_, ok = s.Get("expired")
	assert.False(t, ok, "expired session must be removed by cleanup")
}

func TestAttestationSessionStore_Put_AtCapacity(t *testing.T) {
	s := NewAttestationSessionStore()
	s.sessions = make(map[string]AttestationSession, maxAttestationSessions)
	for i := range maxAttestationSessions {
		s.sessions[fmt.Sprintf("sess-%d", i)] = AttestationSession{ExpiresAt: time.Now().Add(time.Hour)}
	}

	err := s.Put("overflow", AttestationSession{ExpiresAt: time.Now().Add(time.Hour)})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "capacity")
}

func TestAttestationSessionStore_StartCleanup_ContextCancel(t *testing.T) {
	s := NewAttestationSessionStore()
	ctx, cancel := context.WithCancel(context.Background())
	s.StartCleanup(ctx, 10*time.Millisecond)
	// Cancel and verify the goroutine stops without blocking.
	cancel()
	time.Sleep(50 * time.Millisecond)
}
