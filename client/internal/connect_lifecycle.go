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
	opStatus
	opSignals
)

// lifecycleCmd is a single start/stop/status request handed to the supervisor
// goroutine. All three flow through the same cmdCh so they are strictly
// ordered (FIFO) with respect to each other.
//
// done is the caller-supplied notification channel (nil for fire-and-forget):
//   - for opStart it receives the run's end result when the run terminates, or
//     errAlreadyRunning immediately if a run is already in flight.
//   - for opStop it receives nil once the in-flight run has fully unwound.
//
// reply is used only by opStatus; sigReply only by opSignals.
type lifecycleCmd struct {
	op          lifecycleOp
	config      *profilemanager.Config
	md          metadata.MD
	mobileDep   MobileDependency
	runningChan chan struct{}
	logPath     string
	done        chan error
	reply       chan bool
	sigReply    chan runSignals
}

// runSignals exposes the in-flight run's lifecycle channels to external waiters
// (the daemon's waitForUp/Status). Both are nil when no run is in flight.
type runSignals struct {
	established <-chan struct{} // closed by the run once the connection is established
	done        <-chan error    // receives the run's end result
}

// runEndResult is sent by the run goroutine to the supervisor when a run ends,
// whether on its own (error / external context cancellation) or because of a Stop.
type runEndResult struct {
	err error
}

// runFunc executes a single client run bound to the supervisor-owned context,
// with the config supplied by the start request.
type runFunc func(ctx context.Context, config *profilemanager.Config, mobileDep MobileDependency, runningChan chan struct{}, logPath string) error

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
	// runCancel cancels that run.
	curStart  *lifecycleCmd
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
			case opStatus:
				cmd.reply <- (s.isRunningInternal())
			case opSignals:
				var sig runSignals
				if s.curStart != nil {
					sig = runSignals{established: s.curStart.runningChan, done: s.curStart.done}
				}
				cmd.sigReply <- sig
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

	go func(ctx context.Context, cfg *profilemanager.Config, m MobileDependency, rc chan struct{}, lp string) {
		err := s.run(ctx, cfg, m, rc, lp)
		s.runEnded <- runEndResult{err: err}
	}(runCtx, cmd.config, cmd.mobileDep, cmd.runningChan, cmd.logPath)
}

func (s *supervisor) handleStop(cmd lifecycleCmd) {
	if s.curStart == nil {
		notify(cmd.done, nil)
		return
	}

	// Cancel the in-flight run and block the supervisor until it has fully
	// unwound, so the next queued command (e.g. a fresh start) starts from a
	// clean slate. The run goroutine reports completion via runEnded.
	s.runCancel()
	res := <-s.runEnded
	s.finishRun(res.err)
	notify(cmd.done, nil)
}

// finishRun resets lifecycle state after a run terminates and hands the run
// error back to whoever asked to be notified of the start.
func (s *supervisor) finishRun(err error) {
	s.runCancel = nil
	if s.isRunningInternal() {
		notify(s.curStart.done, err)
		s.curStart = nil
	}
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
func (s *supervisor) startAsync(config *profilemanager.Config, md metadata.MD, mobileDep MobileDependency, runningChan chan struct{}, logPath string, done chan error) {
	cmd := lifecycleCmd{op: opStart, config: config, md: md, mobileDep: mobileDep, runningChan: runningChan, logPath: logPath, done: done}
	select {
	case s.cmdCh <- cmd:
	case <-s.ctx.Done():
		notify(done, s.ctx.Err())
	}
}

// start enqueues a start and blocks until the run terminates, preserving the
// blocking contract of the legacy Run entry points.
func (s *supervisor) start(config *profilemanager.Config, md metadata.MD, mobileDep MobileDependency, runningChan chan struct{}, logPath string) error {
	done := make(chan error, 1)
	s.startAsync(config, md, mobileDep, runningChan, logPath, done)
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
// errNoRunInFlight if no run is in flight. The select runs in the caller's
// goroutine on the run's channels — it does not block the supervisor loop.
func (s *supervisor) waitEstablishedOrDone(ctx context.Context) error {
	sig := s.signals()
	if sig.established == nil {
		return errNoRunInFlight
	}
	select {
	case <-sig.established:
		return nil
	case err := <-sig.done:
		if err != nil {
			return err
		}
		return errStoppedBeforeEstablished
	case <-ctx.Done():
		return ctx.Err()
	}
}

// signals asks the loop for the in-flight run's lifecycle channels, serialized
// with start/stop so the returned pair is consistent. Both nil when idle.
func (s *supervisor) signals() runSignals {
	reply := make(chan runSignals, 1)
	select {
	case s.cmdCh <- lifecycleCmd{op: opSignals, sigReply: reply}:
	case <-s.ctx.Done():
		return runSignals{}
	}
	select {
	case sig := <-reply:
		return sig
	case <-s.ctx.Done():
		return runSignals{}
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
