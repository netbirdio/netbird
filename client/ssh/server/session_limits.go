package server

import (
	"encoding/binary"
	"math"
	"sync/atomic"

	"github.com/gliderlabs/ssh"
	log "github.com/sirupsen/logrus"
	cryptossh "golang.org/x/crypto/ssh"
)

const (
	// maxSessionsPerConn bounds concurrent session channels on one SSH connection.
	maxSessionsPerConn = 64

	// maxDirectTCPIPPerConn bounds concurrent direct-tcpip channels, dialing or
	// relaying, on one SSH connection.
	maxDirectTCPIPPerConn = 512

	// maxEnvRequests and maxEnvPayload bound the environment a single session can
	// accumulate before its command starts.
	maxEnvRequests = 128
	maxEnvPayload  = 8 * 1024

	// maxQueuedRequests and maxQueuedBytes bound the requests held for a session whose
	// request loop is not consuming them. A client that exceeds either has its channel
	// closed.
	maxQueuedRequests = 128
	maxQueuedBytes    = 256 * 1024
)

type (
	sessionCountKey     struct{}
	directTCPIPCountKey struct{}
)

// sessionChannelHandler serves "session" channels like ssh.DefaultSessionHandler, with
// the per-connection session count capped, the request stream bounded, and any panic
// from the session request loop contained to its channel.
func (s *Server) sessionChannelHandler(srv *ssh.Server, conn *cryptossh.ServerConn, newChan cryptossh.NewChannel, ctx ssh.Context) {
	release, ok := acquireConnSlot(ctx, sessionCountKey{}, maxSessionsPerConn)
	if !ok {
		if err := newChan.Reject(cryptossh.ResourceShortage, "too many sessions"); err != nil {
			log.Debugf("reject session channel: %v", err)
		}
		return
	}
	defer release()

	guarded := &guardedSessionChannel{NewChannel: newChan}
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		log.Errorf("SSH session request loop panicked from %s: %v", ctx.RemoteAddr(), r)
		guarded.closeChannel()
	}()

	ssh.DefaultSessionHandler(srv, conn, guarded, ctx)
}

// drainWindowChanges discards window changes until winCh is closed. It must run after
// the session's command handler has returned.
func drainWindowChanges(winCh <-chan ssh.Window) {
	go func() {
		for range winCh {
		}
	}()
}

// acquireConnSlot takes one of limit slots counted under key for the connection that
// ctx belongs to. The returned func releases the slot.
func acquireConnSlot(ctx ssh.Context, key any, limit int32) (func(), bool) {
	counter := connCounter(ctx, key)
	if counter.Add(1) > limit {
		counter.Add(-1)
		return nil, false
	}
	return func() { counter.Add(-1) }, true
}

func connCounter(ctx ssh.Context, key any) *atomic.Int32 {
	ctx.Lock()
	defer ctx.Unlock()

	if c, ok := ctx.Value(key).(*atomic.Int32); ok {
		return c
	}
	c := new(atomic.Int32)
	ctx.SetValue(key, c)
	return c
}

// guardedSessionChannel hands the session loop a filtered request stream.
type guardedSessionChannel struct {
	cryptossh.NewChannel
	ch atomic.Pointer[cryptossh.Channel]
}

// Accept accepts the channel and returns its requests after filtering.
func (g *guardedSessionChannel) Accept() (cryptossh.Channel, <-chan *cryptossh.Request, error) {
	ch, reqs, err := g.NewChannel.Accept()
	if err != nil {
		return nil, nil, err
	}
	g.ch.Store(&ch)
	return ch, filterSessionRequests(ch, reqs), nil
}

func (g *guardedSessionChannel) closeChannel() {
	if ch := g.ch.Load(); ch != nil {
		_ = (*ch).Close()
	}
}

// refusedRequestType is the type given to a request the filter refuses. The session
// loop answers unknown request types with a failure reply, so a refused request is
// answered by the loop itself and in its position among the replies, which the
// protocol requires since replies carry no request identifier.
const refusedRequestType = "refused@netbird.io"

// requestFilter passes session channel requests to the session loop while keeping
// what the loop can accumulate or block on bounded:
//   - a malformed pty-req is refused instead of reaching the loop's parser
//   - env requests beyond maxEnvRequests, or with an oversized payload, are refused
//   - window-change requests are refused unless the session's command is a shell or
//     exec, and coalesced after it starts, as the loop blocks sending on a one-slot
//     channel that only a shell or exec handler drains. Subsystems never read it.
//   - request types the loop does not act on are refused, which also drops their payload
//   - the queue behind a stalled loop is capped by count and by payload bytes, after
//     which the channel is closed
type requestFilter struct {
	ch          cryptossh.Channel
	queue       []queuedRequest
	queuedBytes int
	lastWinch   *cryptossh.Request
	envCount    int

	// commandSeen is set by the first shell, exec or subsystem request, which decides
	// the session's command as far as the loop is concerned.
	commandSeen bool
	// started is set when that first command is a shell or exec.
	started bool
}

// queuedRequest remembers the payload size counted against the queue when the request
// was added, as a refusal later drops the payload.
type queuedRequest struct {
	req  *cryptossh.Request
	size int
}

// filterSessionRequests returns the requests of in as the session loop should see them.
func filterSessionRequests(ch cryptossh.Channel, in <-chan *cryptossh.Request) <-chan *cryptossh.Request {
	out := make(chan *cryptossh.Request)
	f := &requestFilter{ch: ch}
	go func() {
		defer close(out)
		f.run(in, out)
	}()
	return out
}

func (f *requestFilter) run(in <-chan *cryptossh.Request, out chan<- *cryptossh.Request) {
	for {
		var (
			sendCh chan<- *cryptossh.Request
			next   *cryptossh.Request
		)
		if len(f.queue) > 0 {
			sendCh = out
			next = f.queue[0].req
		}

		select {
		case req, ok := <-in:
			if !ok {
				return
			}
			if !f.enqueue(req) {
				return
			}
		case sendCh <- next:
			f.dropHead()
		}
	}
}

func (f *requestFilter) dropHead() {
	head := f.queue[0]
	if head.req == f.lastWinch {
		f.lastWinch = nil
	}
	f.queuedBytes -= head.size
	f.queue[0] = queuedRequest{}
	f.queue = f.queue[1:]
}

// enqueue classifies req and queues it. It returns false after closing the channel
// because the queue is full.
func (f *requestFilter) enqueue(req *cryptossh.Request) bool {
	if len(f.queue) >= maxQueuedRequests || f.queuedBytes+len(req.Payload) > maxQueuedBytes {
		log.Warnf("SSH session request queue full, closing channel")
		if f.ch != nil {
			_ = f.ch.Close()
		}
		return false
	}

	switch req.Type {
	case "pty-req":
		if !validPtyReqPayload(req.Payload) {
			refuseRequest(req)
		}
	case "env":
		f.envCount++
		if f.envCount > maxEnvRequests || len(req.Payload) > maxEnvPayload {
			refuseRequest(req)
		}
	case "shell", "exec", "subsystem":
		f.noteCommand(req.Type)
	case "window-change":
		f.coalesceWindowChange(req)
	case "signal", "break", "auth-agent-req@openssh.com":
	default:
		refuseRequest(req)
	}
	f.queue = append(f.queue, queuedRequest{req: req, size: len(req.Payload)})
	f.queuedBytes += len(req.Payload)
	return true
}

func (f *requestFilter) noteCommand(reqType string) {
	if f.commandSeen {
		return
	}
	f.commandSeen = true
	f.started = reqType != "subsystem"
}

func (f *requestFilter) coalesceWindowChange(req *cryptossh.Request) {
	if !f.started || !validWinchPayload(req.Payload) {
		refuseRequest(req)
		return
	}
	if f.lastWinch != nil {
		refuseRequest(f.lastWinch)
	}
	f.lastWinch = req
}

// validWinchPayload reports whether p parses as a window-change payload whose columns and
// rows are non-zero and fit the uint16 the PTY takes. A malformed or unusable replacement
// must not displace a valid queued resize.
func validWinchPayload(p []byte) bool {
	var win struct{ Columns, Rows, Width, Height uint32 }
	if err := cryptossh.Unmarshal(p, &win); err != nil {
		return false
	}
	return usablePtyDimension(win.Columns) && usablePtyDimension(win.Rows)
}

func usablePtyDimension(v uint32) bool {
	return v > 0 && v <= math.MaxUint16
}

func refuseRequest(req *cryptossh.Request) {
	req.Type = refusedRequestType
	req.Payload = nil
}

// validPtyReqPayload reports whether p holds a term string followed by the two
// uint32 window dimensions, without overflowing on a hostile string length. The
// dimensions must fit the Windows int16 ConPty coordinate, which is narrower than the
// Unix uint16 winsize; zero is allowed and defaulted by the Unix path.
func validPtyReqPayload(p []byte) bool {
	if len(p) < 4 {
		return false
	}
	termLen := uint64(binary.BigEndian.Uint32(p))
	if uint64(len(p)) < 4+termLen+8 {
		return false
	}
	dims := p[4+termLen:]
	return binary.BigEndian.Uint32(dims) <= math.MaxInt16 &&
		binary.BigEndian.Uint32(dims[4:]) <= math.MaxInt16
}
