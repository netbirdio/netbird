package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/proto"
)

// The daemon takes guardedConfigMu before s.mutex. authorizeAndPrepareLogin
// takes s.mutex while holding guardedConfigMu, so a SetConfig that grabbed
// s.mutex first and then waited for guardedConfigMu would deadlock the daemon
// against a concurrent login: two unprivileged IPC calls are enough.
//
// The held guardedConfigMu below stands in for that login. While SetConfig waits
// for it, s.mutex must stay free, otherwise the login waiting for s.mutex could
// never release guardedConfigMu.
func TestSetConfig_TakesGuardedConfigMuBeforeServerMutex(t *testing.T) {
	s, ctx, profName, username, _ := setupServerWithProfile(t)

	s.guardedConfigMu.Lock()

	done := make(chan error, 1)
	go func() {
		_, err := s.SetConfig(ctx, &proto.SetConfigRequest{
			ProfileName: profName,
			Username:    username,
		})
		done <- err
	}()

	require.Never(t, func() bool {
		if !s.mutex.TryLock() {
			return true
		}
		s.mutex.Unlock()
		return false
	}, 500*time.Millisecond, 10*time.Millisecond,
		"SetConfig held s.mutex while waiting for guardedConfigMu, which deadlocks against a concurrent login")

	s.guardedConfigMu.Unlock()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("SetConfig did not finish after guardedConfigMu was released")
	}
}
