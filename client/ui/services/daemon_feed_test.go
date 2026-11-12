//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/proto"
)

// unreachableDaemon fails every call with Unavailable.
type unreachableDaemon struct {
	proto.DaemonServiceClient
}

func (unreachableDaemon) Status(context.Context, *proto.StatusRequest, ...grpc.CallOption) (*proto.StatusResponse, error) {
	return nil, gstatus.Error(codes.Unavailable, "connection error")
}

func (unreachableDaemon) SubscribeStatus(context.Context, *proto.StatusRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[proto.StatusResponse], error) {
	return nil, gstatus.Error(codes.Unavailable, "connection error")
}

// probingConn is a DaemonConn whose socket probe reports denied.
type probingConn struct {
	stubConn
	denied bool
}

func (c probingConn) DeniesCaller(context.Context) bool { return c.denied }

type recordingEmitter struct {
	mu     sync.Mutex
	events []Status
	got    chan struct{}
}

func (e *recordingEmitter) Emit(name string, data ...any) bool {
	if name != EventStatusSnapshot {
		return true
	}
	e.mu.Lock()
	e.events = append(e.events, data[0].(Status))
	e.mu.Unlock()
	select {
	case e.got <- struct{}{}:
	default:
	}
	return true
}

func TestDaemonFeedGet_TellsDenialFromNotRunning(t *testing.T) {
	tests := []struct {
		name string
		conn DaemonConn
		want string
	}{
		{"socket refuses the user", probingConn{stubConn: stubConn{client: unreachableDaemon{}}, denied: true}, StatusDaemonAccessDenied},
		{"daemon not running", probingConn{stubConn: stubConn{client: unreachableDaemon{}}}, StatusDaemonUnavailable},
		{"conn cannot probe", stubConn{client: unreachableDaemon{}}, StatusDaemonUnavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			feed := &DaemonFeed{conn: tt.conn}
			st, err := feed.Get(context.Background())
			require.NoError(t, err)
			assert.Equal(t, tt.want, st.Status, "synthetic status for an unreachable daemon")
		})
	}
}

// The denial is emitted once across stream retries.
func TestDaemonFeedStream_EmitsDenialOnce(t *testing.T) {
	emitter := &recordingEmitter{got: make(chan struct{}, 1)}
	feed := &DaemonFeed{
		conn:    probingConn{stubConn: stubConn{client: unreachableDaemon{}}, denied: true},
		emitter: emitter,
	}

	ctx, cancel := context.WithCancel(context.Background())
	feed.streamWg.Add(1)
	go feed.statusStreamLoop(ctx)

	select {
	case <-emitter.got:
	case <-time.After(5 * time.Second):
		t.Fatal("no status emitted")
	}
	// Let at least one retry run past the first attempt.
	time.Sleep(1500 * time.Millisecond)
	cancel()
	feed.streamWg.Wait()

	emitter.mu.Lock()
	defer emitter.mu.Unlock()
	require.NotEmpty(t, emitter.events)
	assert.Len(t, emitter.events, 1, "the outage is reported once across retries")
	assert.Equal(t, StatusDaemonAccessDenied, emitter.events[0].Status, "the denial, not not-running")
}

func TestIsDaemonOutage(t *testing.T) {
	assert.True(t, IsDaemonOutage(StatusDaemonUnavailable), "not running is an outage")
	assert.True(t, IsDaemonOutage(StatusDaemonAccessDenied), "a refused user is an outage")
	assert.False(t, IsDaemonOutage(StatusConnected), "a live daemon is not")
}
