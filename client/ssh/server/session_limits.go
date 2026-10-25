package server

import (
	"encoding/binary"
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

	// maxQueuedRequests bounds the requests held for a session whose request loop is
	// not consuming them. A client that exceeds it has its channel closed.
	maxQueuedRequests = 256
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

// sessionRequest is a request waiting for the session loop. A request that is not
// forwarded is answered with reply when it reaches the head of the queue, which keeps
// replies in request order as the protocol requires.
type sessionRequest struct {
	req     *cryptossh.Request
	forward bool
	reply   bool
}

func (r *sessionRequest) refuse() {
	r.forward, r.reply = false, false
}

func (r *sessionRequest) accept() {
	r.forward, r.reply = false, true
}

// requestFilter passes session channel requests to the session loop while keeping
// what the loop can accumulate or block on bounded:
//   - a malformed pty-req is refused instead of reaching the loop's parser
//   - env requests beyond maxEnvRequests, or with an oversized payload, are refused
//   - window-change requests are dropped until the command starts and coalesced
//     after, as the loop blocks sending on a one-slot channel that only the command
//     handler drains
//   - the queue behind a stalled loop is capped, after which the channel is closed
type requestFilter struct {
	ch        cryptossh.Channel
	queue     []*sessionRequest
	lastWinch *sessionRequest
	started   bool
	envCount  int
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
		f.replyToDecided()

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

// replyToDecided answers, in order, the requests at the head of the queue that are not
// forwarded.
func (f *requestFilter) replyToDecided() {
	for len(f.queue) > 0 && !f.queue[0].forward {
		head := f.queue[0]
		if err := head.req.Reply(head.reply, nil); err != nil {
			log.Debugf("reply to session request: %v", err)
		}
		f.queue = f.queue[1:]
	}
}

func (f *requestFilter) dropHead() {
	if f.queue[0] == f.lastWinch {
		f.lastWinch = nil
	}
	f.queue = f.queue[1:]
}

// enqueue classifies req and queues it. It returns false after closing the channel
// because the queue is full.
func (f *requestFilter) enqueue(req *cryptossh.Request) bool {
	if len(f.queue) >= maxQueuedRequests {
		log.Warnf("SSH session request queue full, closing channel")
		_ = f.ch.Close()
		return false
	}

	item := &sessionRequest{req: req, forward: true}
	switch req.Type {
	case "pty-req":
		if !validPtyReqPayload(req.Payload) {
			item.refuse()
		}
	case "env":
		f.envCount++
		if f.envCount > maxEnvRequests || len(req.Payload) > maxEnvPayload {
			item.refuse()
		}
	case "shell", "exec", "subsystem":
		f.started = true
	case "window-change":
		f.coalesceWindowChange(item)
	}
	f.queue = append(f.queue, item)
	return true
}

func (f *requestFilter) coalesceWindowChange(item *sessionRequest) {
	if !f.started {
		item.accept()
		return
	}
	if f.lastWinch != nil {
		f.lastWinch.accept()
	}
	f.lastWinch = item
}

// validPtyReqPayload reports whether p holds a term string followed by the two
// uint32 window dimensions, without overflowing on a hostile string length.
func validPtyReqPayload(p []byte) bool {
	if len(p) < 4 {
		return false
	}
	termLen := uint64(binary.BigEndian.Uint32(p))
	return uint64(len(p)) >= 4+termLen+8
}
