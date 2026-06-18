package internal

import (
	"context"
	"errors"

	"google.golang.org/grpc/metadata"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

// errAlreadyRunning is returned when a start is requested while a run is already
// in flight.
var errAlreadyRunning = errors.New("client is already running")

// errNoRunInFlight is returned by waitEstablishedOrDone when no run is active.
var errNoRunInFlight = errors.New("no connection run in flight")

// errStoppedBeforeEstablished is returned when a run ended (cleanly) before the
// connection was established.
var errStoppedBeforeEstablished = errors.New("run stopped before the connection was established")

// lifecycleOp is a serialized lifecycle operation processed by the supervisor.
type lifecycleOp int

const (
	opStart lifecycleOp = iota
	opStop
	opRestart
	opStatus
	opWaitEstablished
)

// lifecycleCmd is a single lifecycle request handed to the supervisor goroutine.
// They all flow through the same cmdCh so they are strictly ordered (FIFO) with
// respect to each other.
type lifecycleCmd struct {
	op        lifecycleOp
	config    *profilemanager.Config
	md        metadata.MD
	mobileDep MobileDependency
	logPath   string

	// done is the caller's notification channel (nil for fire-and-forget). Its
	// meaning depends on op:
	//   - opStart: receives the run's end result when the run terminates, or
	//     errAlreadyRunning immediately if a run is already in flight.
	//   - opStop: receives nil once the in-flight run has fully unwound.
	//   - opWaitEstablished: receives the wait outcome (see waitEstablishedOrDone).
	done chan error

	reply   chan bool       // opStatus only: receives whether a run is in flight
	waitCtx context.Context // opWaitEstablished only: the waiter's cancellation context
}

// runState holds the lifecycle channels of a single in-flight run, owned by the
// loop goroutine. It never escapes the supervisor as an API; the only readers
// are the per-wait goroutines the loop spawns for opWaitEstablished.
//
// connEstablishedChan is closed by the run once the connection is established.
// The supervisor creates and owns it — callers no longer supply it; they observe
// it through waitEstablishedOrDone. ended is closed (broadcast) when the run
// terminates, so any number of waiters can observe it; err is the run's end
// result, valid only after ended is closed.
type runState struct {
	connEstablishedChan chan struct{} // closed by the run on established
	ended               chan struct{} // closed by finishRun when the run terminates
	err                 error         // run end result, valid after ended is closed
}

// runEndResult is sent by the run goroutine to the supervisor when a run ends,
// whether on its own (error / external context cancellation) or because of a Stop.
type runEndResult struct {
	err error
}

// runFunc executes a single client run bound to the supervisor-owned context,
// with the config supplied by the start request.
type runFunc func(ctx context.Context, config *profilemanager.Config, mobileDep MobileDependency, connEstablishedChan chan struct{}, logPath string) error

// supervisor serializes start/stop of a single client run. Every request goes
// through cmdCh and is handled one at a time by the loop goroutine, so two
// lifecycle operations can never overlap and their order is preserved (FIFO).
// The loop goroutine is the sole owner of curStart/runCancel, so that state
// needs no locking. The loop exits when the parent context is cancelled.
type supervisor struct {
	ctx      context.Context
	run      runFunc
	cmdCh    chan lifecycleCmd
	runEnded chan runEndResult

	// owned exclusively by the loop goroutine. curStart is the in-flight start
	// command (nil = idle); its done channel is notified when the run ends.
	// curRun holds that run's lifecycle channels; runCancel cancels it.
	curStart  *lifecycleCmd
	curRun    *runState
	runCancel context.CancelFunc
}

func newSupervisor(ctx context.Context, run runFunc) *supervisor {
	s := &supervisor{
		ctx:      ctx,
		run:      run,
		cmdCh:    make(chan lifecycleCmd, 16),
		runEnded: make(chan runEndResult, 1),
	}
	go s.loop()
	return s
}

func (s *supervisor) loop() {
	for {
		select {
		case <-s.ctx.Done():
			s.shutdown()
			return
		case cmd := <-s.cmdCh:
			switch cmd.op {
			case opStart:
				s.handleStart(cmd)
			case opStop:
				s.handleStop(cmd)
			case opRestart:
				s.handleRestart(cmd)
			case opStatus:
				cmd.reply <- (s.isRunningInternal())
			case opWaitEstablished:
				s.handleWaitEstablished(cmd)
			}
		case res := <-s.runEnded:
			// Run ended on its own, without an explicit Stop.
			s.finishRun(res.err)
		}
	}
}

func (s *supervisor) handleStart(cmd lifecycleCmd) {
	if s.isRunningInternal() {
		notify(cmd.done, errAlreadyRunning)
		return
	}

	runCtx, cancel := context.WithCancel(s.ctx)
	if cmd.md != nil {
		// Carry caller-supplied gRPC metadata (e.g. UI user-agent) into the run
		// context so the engine's management/signal calls forward it. The cancel
		// still drives runCtx (metadata wrapping preserves cancellation).
		runCtx = metadata.NewOutgoingContext(runCtx, cmd.md)
	}
	s.runCancel = cancel
	s.curStart = &cmd
	s.curRun = &runState{connEstablishedChan: make(chan struct{}), ended: make(chan struct{})}

	go func(ctx context.Context, cfg *profilemanager.Config, m MobileDependency, established chan struct{}, lp string) {
		err := s.run(ctx, cfg, m, established, lp)
		s.runEnded <- runEndResult{err: err}
	}(runCtx, cmd.config, cmd.mobileDep, s.curRun.connEstablishedChan, cmd.logPath)
}

func (s *supervisor) handleStop(cmd lifecycleCmd) {
	if !s.isRunningInternal() {
		notify(cmd.done, nil)
		return
	}
	s.stopCurrentRun()
	notify(cmd.done, nil)
}

// handleRestart tears down any in-flight run and starts a fresh one in a single
// loop turn. No other command can interleave between the stop and the start
// (the loop is single-threaded), so the swap is atomic without relying on any
// daemon-side lock — that is what an explicit restart (e.g. MDM config change)
// needs to avoid a window where the client is observably stopped.
func (s *supervisor) handleRestart(cmd lifecycleCmd) {
	if s.isRunningInternal() {
		s.stopCurrentRun()
	}
	s.handleStart(cmd)
}

// stopCurrentRun cancels the in-flight run and blocks the supervisor until it
// has fully unwound, so the next action starts from a clean slate. The run
// goroutine reports completion via runEnded. Caller must hold an in-flight run
// (curStart != nil).
func (s *supervisor) stopCurrentRun() {
	s.runCancel()
	res := <-s.runEnded
	s.finishRun(res.err)
}

// finishRun resets lifecycle state after a run terminates and hands the run
// error back to whoever asked to be notified of the start.
func (s *supervisor) finishRun(err error) {
	s.runCancel = nil
	if s.isRunningInternal() {
		// Publish the result to the broadcast channel before nil-ing curRun, so
		// any opWaitEstablished goroutines blocked on ended observe err.
		s.curRun.err = err
		close(s.curRun.ended)
		s.curRun = nil

		notify(s.curStart.done, err)
		s.curStart = nil
	}
}

// handleWaitEstablished answers an opWaitEstablished request. The select itself
// runs in a spawned goroutine on the run's channels so it never blocks the loop;
// the loop only snapshots the in-flight run's channels (which it owns) here.
func (s *supervisor) handleWaitEstablished(cmd lifecycleCmd) {
	caller := cmd.done
	if !s.isRunningInternal() {
		notify(caller, errNoRunInFlight)
		return
	}
	rs := s.curRun
	established := rs.connEstablishedChan
	ctx := cmd.waitCtx
	go func() {
		select {
		case <-established:
			notify(caller, nil)
		case <-rs.ended:
			if rs.err != nil {
				notify(caller, rs.err)
				return
			}
			notify(caller, errStoppedBeforeEstablished)
		case <-ctx.Done():
			notify(caller, ctx.Err())
		}
	}()
}

// shutdown tears down the in-flight run when the parent context is cancelled,
// then fails any still-queued commands so their callers never hang.
func (s *supervisor) shutdown() {
	if s.runCancel != nil {
		s.runCancel()
		res := <-s.runEnded
		s.finishRun(res.err)
	}
	for {
		select {
		case cmd := <-s.cmdCh:
			notify(cmd.done, s.ctx.Err())
		default:
			return
		}
	}
}

// startAsync enqueues a start without blocking. If done is non-nil it receives
// the run's end result (or errAlreadyRunning on rejection, or the context error
// on shutdown).
func (s *supervisor) startAsync(config *profilemanager.Config, md metadata.MD, mobileDep MobileDependency, logPath string, done chan error) {
	cmd := lifecycleCmd{op: opStart, config: config, md: md, mobileDep: mobileDep, logPath: logPath, done: done}
	select {
	case s.cmdCh <- cmd:
	case <-s.ctx.Done():
		notify(done, s.ctx.Err())
	}
}

// restartAsync enqueues an atomic stop+start without blocking. The supervisor
// tears down any in-flight run and starts a fresh one with the supplied config
// in a single loop turn (see handleRestart). Fire-and-forget: the new run owns
// its lifecycle channels, observed via waitEstablishedOrDone.
func (s *supervisor) restartAsync(config *profilemanager.Config, md metadata.MD, mobileDep MobileDependency, logPath string) {
	cmd := lifecycleCmd{op: opRestart, config: config, md: md, mobileDep: mobileDep, logPath: logPath}
	select {
	case s.cmdCh <- cmd:
	case <-s.ctx.Done():
	}
}

// start enqueues a start and blocks until the run terminates, preserving the
// blocking contract of the legacy Run entry points.
func (s *supervisor) start(config *profilemanager.Config, md metadata.MD, mobileDep MobileDependency, logPath string) error {
	done := make(chan error, 1)
	s.startAsync(config, md, mobileDep, logPath, done)
	select {
	case err := <-done:
		return err
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}

// isRunning asks the loop whether a run is in flight. The query is serialized
// with start/stop, so during a stop it waits for the teardown to settle and
// then reports the final state — never a transient "half-stopped".
func (s *supervisor) isRunning() bool {
	reply := make(chan bool, 1)
	select {
	case s.cmdCh <- lifecycleCmd{op: opStatus, reply: reply}:
	case <-s.ctx.Done():
		return false
	}
	select {
	case r := <-reply:
		return r
	case <-s.ctx.Done():
		return false
	}
}

func (s *supervisor) isRunningInternal() bool {
	return s.curStart != nil
}

// waitEstablishedOrDone blocks until the in-flight run becomes established
// (returns nil) or ends before that (returns the run error, or
// errStoppedBeforeEstablished on a clean stop), or ctx is cancelled. Returns
// errNoRunInFlight if no run is in flight. The wait is performed by a goroutine
// spawned inside the loop (see handleWaitEstablished); the run's channels never
// leave the supervisor.
func (s *supervisor) waitEstablishedOrDone(ctx context.Context) error {
	reply := make(chan error, 1)
	select {
	case s.cmdCh <- lifecycleCmd{op: opWaitEstablished, waitCtx: ctx, done: reply}:
	case <-ctx.Done():
		return ctx.Err()
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
	select {
	case err := <-reply:
		return err
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}

// stop enqueues a stop and blocks until the in-flight run is fully torn down.
func (s *supervisor) stop() error {
	done := make(chan error, 1)
	select {
	case s.cmdCh <- lifecycleCmd{op: opStop, done: done}:
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
	select {
	case err := <-done:
		return err
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}

// notify sends on a caller-supplied channel without blocking. The channel is
// expected to be buffered (cap 1); a nil channel means the caller did not ask
// to be notified.
func notify(ch chan error, err error) {
	if ch == nil {
		return
	}
	select {
	case ch <- err:
	default:
	}
}
