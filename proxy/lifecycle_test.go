package proxy

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// quietLifecycleLogger keeps lifecycle tests from spamming the test output.
func quietLifecycleLogger() *log.Logger {
	l := log.New()
	l.SetOutput(io.Discard)
	l.SetLevel(log.PanicLevel)
	return l
}

func TestNewIsPureConstructor(t *testing.T) {
	cfg := Config{
		ListenAddr:        ":0",
		ID:                "test-id",
		Logger:            quietLifecycleLogger(),
		Version:           "test",
		ManagementAddress: "https://example.invalid",
		HealthAddr:        "",
		ForwardedProto:    "auto",
	}

	srv := New(cfg)
	require.NotNil(t, srv, "New must return a non-nil Server")

	assert.Equal(t, ":0", srv.ListenAddr, "ListenAddr should round-trip")
	assert.Equal(t, "test-id", srv.ID, "ID should round-trip")
	assert.Equal(t, "test", srv.Version, "Version should round-trip")
	assert.Equal(t, "https://example.invalid", srv.ManagementAddress, "ManagementAddress should round-trip")
	assert.Equal(t, "auto", srv.ForwardedProto, "ForwardedProto should round-trip")

	// Pure constructor: no goroutines, no listener bind, no management dial.
	assert.False(t, srv.started, "Server must be marked unstarted before Start")
	assert.Nil(t, srv.mgmtClient, "mgmt client must not be created in New")
	assert.Nil(t, srv.netbird, "netbird client must not be created in New")
	assert.Nil(t, srv.https, "https server must not be created in New")
	assert.Nil(t, srv.healthServer, "health server must not be created in New")
	assert.Nil(t, srv.runCancel, "runCancel must be nil before Start")
	assert.Nil(t, srv.runErrCh, "runErrCh must be nil before Start")
}

func TestStopBeforeStartIsNoOp(t *testing.T) {
	srv := New(Config{Logger: quietLifecycleLogger()})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err := srv.Stop(ctx)
	assert.NoError(t, err, "Stop on an unstarted server must succeed without error")

	err = srv.Stop(ctx)
	assert.NoError(t, err, "Stop must remain idempotent across repeated calls")
}

func TestStartFailsWithoutManagement(t *testing.T) {
	srv := New(Config{
		Logger:            quietLifecycleLogger(),
		ListenAddr:        "127.0.0.1:0",
		ManagementAddress: "://broken-url",
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err := srv.Start(ctx)
	require.Error(t, err, "Start must surface management dial failures")

	assert.True(t, srv.started, "started flag is set before any dial attempt so a second Start fails fast")

	err = srv.Start(ctx)
	require.Error(t, err, "second Start must reject")
	assert.Contains(t, err.Error(), "already started", "error must explain why the call was rejected")
}

func TestStopIsIdempotent(t *testing.T) {
	srv := &Server{
		Logger:    quietLifecycleLogger(),
		started:   true,
		runErrCh:  make(chan struct{}),
		runCancel: func() {},
	}
	srv.recordRunErr(errors.New("synthetic"))

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err := srv.Stop(ctx)
	require.Error(t, err, "Stop must surface the recorded background error")
	assert.Contains(t, err.Error(), "synthetic", "error must round-trip recordRunErr's value")

	err = srv.Stop(ctx)
	require.Error(t, err, "second Stop must still report the same error")
	assert.Contains(t, err.Error(), "synthetic", "idempotent Stop must return the cached error")
}

func TestRecordRunErrPreservesFirstFailure(t *testing.T) {
	srv := &Server{
		Logger:   quietLifecycleLogger(),
		runErrCh: make(chan struct{}),
	}

	srv.recordRunErr(errors.New("first"))
	srv.recordRunErr(errors.New("second"))

	require.Error(t, srv.runErr, "first failure must be retained")
	assert.Contains(t, srv.runErr.Error(), "first", "second call must not overwrite the cached error")

	select {
	case <-srv.runErrCh:
	default:
		t.Fatal("recordRunErr must close runErrCh so waitAndStop unblocks")
	}
}

func TestStopSkipsShutdownWhenNeverStarted(t *testing.T) {
	srv := New(Config{Logger: quietLifecycleLogger()})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := srv.Stop(ctx)
	assert.NoError(t, err, "Stop on an unstarted server should not block on the cancelled ctx")
}
