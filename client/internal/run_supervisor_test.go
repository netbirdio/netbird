package internal

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newSupervisedClient() *ConnectClient {
	return NewConnectClient(context.Background(), nil, nil)
}

func TestRunSupervisorPublishRejectsSupersededRun(t *testing.T) {
	var s RunSupervisor
	ctx := context.Background()

	staleGen, staleDone := s.Begin()
	defer close(staleDone)

	freshGen, freshDone := s.Begin()
	defer close(freshDone)

	fresh := newSupervisedClient()
	require.True(t, s.Publish(ctx, freshGen, fresh))

	assert.False(t, s.Publish(ctx, staleGen, newSupervisedClient()))
	assert.Same(t, fresh, s.Current())
}

func TestRunSupervisorPublishStopsDisplacedClient(t *testing.T) {
	var s RunSupervisor
	ctx := context.Background()

	generation, done := s.Begin()
	defer close(done)

	displaced := newSupervisedClient()
	require.True(t, s.Publish(ctx, generation, displaced))

	replacement := newSupervisedClient()
	require.True(t, s.Publish(ctx, generation, replacement))

	assert.Same(t, replacement, s.Current())
	assert.Error(t, displaced.ctx.Err(), "the displaced client's run context should be cancelled")
}

func TestRunSupervisorStopInvalidatesRunInFlight(t *testing.T) {
	var s RunSupervisor
	ctx := context.Background()

	generation, done := s.Begin()
	close(done)

	require.NoError(t, s.Stop(ctx))

	assert.False(t, s.Publish(ctx, generation, newSupervisedClient()))
	assert.Nil(t, s.Current())
}

func TestRunSupervisorStopWaitsForRunExit(t *testing.T) {
	var s RunSupervisor

	_, done := s.Begin()

	stopped := make(chan error, 1)
	go func() { stopped <- s.Stop(context.Background()) }()

	select {
	case <-stopped:
		t.Fatal("Stop returned before the run signalled its exit")
	case <-time.After(50 * time.Millisecond):
	}

	close(done)

	select {
	case err := <-stopped:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("Stop did not return after the run exited")
	}
}

func TestRunSupervisorStopGivesUpWaitOnContext(t *testing.T) {
	var s RunSupervisor

	_, done := s.Begin()
	defer close(done)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	assert.ErrorIs(t, s.Stop(ctx), context.DeadlineExceeded)
}

func TestRunSupervisorDoneSurvivesStop(t *testing.T) {
	var s RunSupervisor

	_, done := s.Begin()
	close(done)

	require.NoError(t, s.Stop(context.Background()))

	runDone := s.Done()
	require.NotNil(t, runDone, "a waiter that raced Stop must still observe the run's exit")
	select {
	case <-runDone:
	default:
		t.Fatal("the last run's exit signal should remain readable after Stop")
	}
}

func TestRunSupervisorAliveTracksRun(t *testing.T) {
	var s RunSupervisor

	assert.False(t, s.Alive(), "no run has started")

	_, done := s.Begin()
	assert.True(t, s.Alive(), "a run is in flight")

	close(done)
	assert.False(t, s.Alive(), "the run signalled its exit")
}

func TestRunSupervisorStopWithoutRunIsNoop(t *testing.T) {
	var s RunSupervisor

	require.NoError(t, s.Stop(context.Background()))
	assert.Nil(t, s.Current())
}
