package client

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/hbwatch"
)

func countLogs(h *logtest.Hook, prefix string) int {
	n := 0
	for _, e := range h.AllEntries() {
		if strings.HasPrefix(e.Message, prefix) {
			n++
		}
	}
	return n
}

// The relay reconnect backoff runs out on the wall clock: after the phone slept
// past it, the device wake picks a server at once instead of after more awake
// seconds.
func TestGuardRetryAtWake(t *testing.T) {
	clk := &jumpClock{now: time.Now()}
	w := hbwatch.New(clk, time.Minute)
	t.Cleanup(hbwatch.SetDefault(w))
	hook := &logtest.Hook{}
	old := log.StandardLogger().ReplaceHooks(log.LevelHooks{})
	log.AddHook(hook)
	t.Cleanup(func() { log.StandardLogger().ReplaceHooks(old) })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	sp := &ServerPicker{PeerID: "test", ConnectionTimeout: 300 * time.Millisecond}
	sp.ServerURLs.Store([]string{"rel://" + addr})
	g := NewGuard(sp, 0, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.StartReconnectTrys(ctx, nil)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	const picks, failures = "try to pick up a new Relay server", "failed to pick new Relay server"
	require.Eventually(t, func() bool { return countLogs(hook, failures) == 1 }, 3*time.Second, 5*time.Millisecond,
		"the first pick fails")
	// The backoff is at least 1 s; the wait has started once the failure is logged.
	time.Sleep(20 * time.Millisecond)
	clk.jump(3 * time.Minute)
	w.SetDeviceAsleep(false)
	require.Eventually(t, func() bool { return countLogs(hook, picks) == 2 }, 500*time.Millisecond, 5*time.Millisecond,
		"the device wake past the wall deadline picks again before the timer")
}
