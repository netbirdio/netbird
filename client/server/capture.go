package server

import (
	"context"
	"io"
	"os"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/util/capture"
)

const maxBundleCaptureDuration = 10 * time.Minute

// bundleCapture holds the state of an in-progress capture destined for the
// debug bundle. The lifecycle is:
//
//	StartBundleCapture → capture running, writing to temp file
//	StopBundleCapture  → capture stopped, temp file available
//	DebugBundle        → temp file included in zip, then cleaned up
type bundleCapture struct {
	mu      sync.Mutex
	sess    *capture.Session
	file    *os.File
	engine  *internal.Engine
	cancel  context.CancelFunc
	stopped bool
}

// stop halts the capture session and closes the pcap writer. Idempotent.
func (bc *bundleCapture) stop() {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	if bc.stopped {
		return
	}
	bc.stopped = true

	if bc.cancel != nil {
		bc.cancel()
	}
	if bc.sess != nil {
		bc.sess.Stop()
	}
}

// path returns the temp file path, or "" if no file exists.
func (bc *bundleCapture) path() string {
	if bc.file == nil {
		return ""
	}
	return bc.file.Name()
}

// cleanup removes the temp file.
func (bc *bundleCapture) cleanup() {
	if bc.file == nil {
		return
	}
	name := bc.file.Name()
	if err := bc.file.Close(); err != nil {
		log.Debugf("close bundle capture file: %v", err)
	}
	if err := os.Remove(name); err != nil && !os.IsNotExist(err) {
		log.Debugf("remove bundle capture file: %v", err)
	}
	bc.file = nil
}

// StartCapture streams a pcap or text packet capture over gRPC.
// Gated by the --enable-capture service flag.
func (s *Server) StartCapture(req *proto.StartCaptureRequest, stream proto.DaemonService_StartCaptureServer) error {
	if !s.captureEnabled {
		return status.Error(codes.PermissionDenied,
			"packet capture is disabled; reinstall or reconfigure the service with --enable-capture")
	}

	if d := req.GetDuration(); d != nil && d.AsDuration() < 0 {
		return status.Error(codes.InvalidArgument, "duration must not be negative")
	}

	matcher, err := parseCaptureFilter(req)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "invalid filter: %v", err)
	}

	pr, pw := io.Pipe()

	opts := capture.Options{
		Matcher: matcher,
		SnapLen: req.GetSnapLen(),
		Verbose: req.GetVerbose(),
		ASCII:   req.GetAscii(),
	}
	if req.GetTextOutput() {
		opts.TextOutput = pw
	} else {
		opts.Output = pw
	}

	sess, err := capture.NewSession(opts)
	if err != nil {
		pw.Close()
		return status.Errorf(codes.Internal, "create capture session: %v", err)
	}

	engine, err := s.claimCapture(sess, func() { pw.Close() })
	if err != nil {
		sess.Stop()
		pw.Close()
		return err
	}

	// Send an empty initial message to signal that the capture was accepted.
	// The client waits for this before printing the banner, so it must arrive
	// before any packet data.
	if err := stream.Send(&proto.CapturePacket{}); err != nil {
		s.clearCaptureIfOwner(sess, engine)
		sess.Stop()
		pw.Close()
		return status.Errorf(codes.Internal, "send initial message: %v", err)
	}

	ctx := stream.Context()
	if d := req.GetDuration(); d != nil {
		if dur := d.AsDuration(); dur > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, dur)
			defer cancel()
		}
	}

	go func() {
		<-ctx.Done()
		s.clearCaptureIfOwner(sess, engine)
		sess.Stop()
		pw.Close()
	}()
	defer pr.Close()

	log.Infof("packet capture started (text=%v, expr=%q)", req.GetTextOutput(), req.GetFilterExpr())
	defer func() {
		stats := sess.Stats()
		log.Infof("packet capture stopped: %d packets, %d bytes, %d dropped",
			stats.Packets, stats.Bytes, stats.Dropped)
	}()

	return streamToGRPC(pr, stream)
}

func streamToGRPC(r io.Reader, stream proto.DaemonService_StartCaptureServer) error {
	buf := make([]byte, 32*1024)
	for {
		n, readErr := r.Read(buf)
		if n > 0 {
			if err := stream.Send(&proto.CapturePacket{Data: buf[:n]}); err != nil {
				log.Debugf("capture stream send: %v", err)
				return nil //nolint:nilerr // client disconnected
			}
		}
		if readErr != nil {
			return nil //nolint:nilerr // pipe closed, capture stopped normally
		}
	}
}

// StartBundleCapture begins capturing packets to a server-side temp file for
// inclusion in the next debug bundle. Not gated by --enable-capture since the
// output stays on the server (same trust level as CPU profiling).
//
// A timeout auto-stops the capture as a safety net if StopBundleCapture is
// never called (e.g. CLI crash).
func (s *Server) StartBundleCapture(_ context.Context, req *proto.StartBundleCaptureRequest) (*proto.StartBundleCaptureResponse, error) {
	s.mutex.Lock()
	// Registered before the unlock so it runs after it: the eviction teardown
	// waits on the evicted session's writer and must not hold s.mutex.
	stopEvicted := func() {}
	defer func() { stopEvicted() }()
	defer s.mutex.Unlock()

	s.stopBundleCaptureLocked()
	s.cleanupBundleCapture()
	stopEvicted = s.evictActiveCaptureLocked()

	engine, err := s.getCaptureEngineLocked()
	if err != nil {
		// Not fatal: kernel mode or not connected. Log and return success
		// so the debug bundle still generates without capture data.
		log.Warnf("packet capture unavailable, skipping: %v", err)
		return &proto.StartBundleCaptureResponse{}, nil
	}

	timeout := req.GetTimeout().AsDuration()
	if timeout <= 0 || timeout > maxBundleCaptureDuration {
		timeout = maxBundleCaptureDuration
	}

	f, err := os.CreateTemp("", "netbird.capture.*.pcap")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "create temp file: %v", err)
	}

	sess, err := capture.NewSession(capture.Options{Output: f})
	if err != nil {
		f.Close()
		os.Remove(f.Name())
		return nil, status.Errorf(codes.Internal, "create capture session: %v", err)
	}

	if err := engine.SetCapture(sess); err != nil {
		sess.Stop()
		f.Close()
		os.Remove(f.Name())
		log.Warnf("packet capture unavailable (no filtered device), skipping: %v", err)
		return &proto.StartBundleCaptureResponse{}, nil
	}
	s.activeCapture = sess

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	bc := &bundleCapture{
		sess:   sess,
		file:   f,
		engine: engine,
		cancel: cancel,
	}

	s.bundleCapture = bc

	go func() {
		<-ctx.Done()
		s.mutex.Lock()
		if s.bundleCapture == bc {
			s.stopBundleCaptureLocked()
		} else {
			bc.stop()
		}
		s.mutex.Unlock()
		log.Infof("bundle capture auto-stopped after timeout")
	}()
	log.Infof("bundle capture started (timeout=%s, file=%s)", timeout, f.Name())

	return &proto.StartBundleCaptureResponse{}, nil
}

// StopBundleCapture stops the running bundle capture. Idempotent.
func (s *Server) StopBundleCapture(_ context.Context, _ *proto.StopBundleCaptureRequest) (*proto.StopBundleCaptureResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.stopBundleCaptureLocked()
	return &proto.StopBundleCaptureResponse{}, nil
}

// stopBundleCaptureLocked stops the bundle capture if running. Must hold s.mutex.
func (s *Server) stopBundleCaptureLocked() {
	if s.bundleCapture == nil {
		return
	}
	bc := s.bundleCapture
	if bc.engine != nil && s.activeCapture == bc.sess {
		if err := bc.engine.SetCapture(nil); err != nil {
			log.Debugf("clear bundle capture: %v", err)
		}
		s.activeCapture = nil
	}
	bc.stop()

	stats := bc.sess.Stats()
	log.Infof("bundle capture stopped: %d packets, %d bytes, %d dropped",
		stats.Packets, stats.Bytes, stats.Dropped)
}

// bundleCapturePath returns the temp file path if a capture has been taken,
// stops any running capture, and returns "". Called from DebugBundle.
// Must hold s.mutex.
func (s *Server) bundleCapturePath() string {
	if s.bundleCapture == nil {
		return ""
	}

	s.bundleCapture.stop()
	return s.bundleCapture.path()
}

// cleanupBundleCapture removes the temp file and clears state. Must hold s.mutex.
func (s *Server) cleanupBundleCapture() {
	if s.bundleCapture == nil {
		return
	}
	s.bundleCapture.cleanup()
	s.bundleCapture = nil
}

// claimCapture reserves the engine's capture slot for sess and installs sess on
// the engine. If another capture is already running it is evicted: a previous
// streaming session whose gRPC client died and never freed the slot stays stuck
// otherwise, and a bundle capture is just informational state. The returned
// engine already has sess installed; the caller must not install it again.
func (s *Server) claimCapture(sess *capture.Session, cancel func()) (*internal.Engine, error) {
	s.mutex.Lock()
	stopEvicted := s.evictActiveCaptureLocked()
	engine, err := s.installCaptureLocked(sess, cancel)
	s.mutex.Unlock()

	// Waits for the evicted session's writer, so it must run outside s.mutex.
	stopEvicted()

	if err != nil {
		return nil, err
	}
	return engine, nil
}

// installCaptureLocked installs sess on the engine and records it as the slot's
// owner, so no other claim can interleave between the two. On failure the slot
// is left unowned. Caller must hold mutex.
func (s *Server) installCaptureLocked(sess *capture.Session, cancel func()) (*internal.Engine, error) {
	engine, err := s.getCaptureEngineLocked()
	if err != nil {
		return nil, err
	}
	if err := engine.SetCapture(sess); err != nil {
		return nil, status.Errorf(codes.Internal, "set capture: %v", err)
	}
	s.activeCapture = sess
	s.activeCaptureCancel = cancel
	return engine, nil
}

// evictActiveCaptureLocked releases the engine's capture slot from whatever
// capture currently owns it so a fresh claim can succeed, and returns the rest
// of that teardown as a function. The returned function is never nil, is safe
// to call more than once, and blocks until the evicted session's writer
// goroutine has exited, so the caller must run it only after releasing
// s.mutex. Caller must hold mutex.
func (s *Server) evictActiveCaptureLocked() func() {
	if s.activeCapture == nil {
		return func() {}
	}
	if s.bundleCapture != nil && s.bundleCapture.sess == s.activeCapture {
		log.Infof("evicting running bundle capture to start a new capture")
		s.stopBundleCaptureLocked()
		return func() {}
	}
	log.Infof("evicting previous streaming capture to start a new one")
	prev := s.activeCapture
	cancel := s.activeCaptureCancel
	if engine, err := s.getCaptureEngineLocked(); err == nil {
		if err := engine.SetCapture(nil); err != nil {
			log.Debugf("clear previous capture: %v", err)
		}
	}
	s.activeCapture = nil
	s.activeCaptureCancel = nil
	return func() {
		// Close the output pipe before waiting: Stop waits for the writer
		// goroutine, which stays blocked in a write for as long as the reader
		// side is open and not draining.
		if cancel != nil {
			cancel()
		}
		prev.Stop()
	}
}

// clearCaptureIfOwner clears engine's capture slot only if sess still owns it.
func (s *Server) clearCaptureIfOwner(sess *capture.Session, engine *internal.Engine) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.activeCapture != sess {
		return
	}
	if err := engine.SetCapture(nil); err != nil {
		log.Debugf("clear capture: %v", err)
	}
	s.activeCapture = nil
	s.activeCaptureCancel = nil
}

func (s *Server) getCaptureEngineLocked() (*internal.Engine, error) {
	if s.connectClient == nil {
		return nil, status.Error(codes.FailedPrecondition, "client not connected")
	}
	engine := s.connectClient.Engine()
	if engine == nil {
		return nil, status.Error(codes.FailedPrecondition, "engine not initialized")
	}
	return engine, nil
}

// parseCaptureFilter returns a Matcher from the request.
// Returns nil (match all) when no filter expression is set.
func parseCaptureFilter(req *proto.StartCaptureRequest) (capture.Matcher, error) {
	expr := req.GetFilterExpr()
	if expr == "" {
		return nil, nil //nolint:nilnil // nil Matcher means "match all"
	}
	return capture.ParseFilter(expr)
}
