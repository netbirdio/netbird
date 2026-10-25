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

// filterSessionRequests passes session channel requests to the session loop while
// keeping what the loop can accumulate or block on bounded:
//   - a malformed pty-req is refused instead of reaching the loop's parser
//   - env requests beyond maxEnvRequests, or with an oversized payload, are refused
//   - window-change requests are dropped until the command starts and coalesced
//     after, as the loop blocks sending on a one-slot channel that only the command
//     handler drains
//   - the queue behind a stalled loop is capped, after which the channel is closed
func filterSessionRequests(ch cryptossh.Channel, in <-chan *cryptossh.Request) <-chan *cryptossh.Request {
	out := make(chan *cryptossh.Request)

	go func() {
		defer close(out)

		var (
			queue     []*sessionRequest
			lastWinch *sessionRequest
			started   bool
			envCount  int
		)

		for {
			for len(queue) > 0 && !queue[0].forward {
				if err := queue[0].req.Reply(queue[0].reply, nil); err != nil {
					log.Debugf("reply to session request: %v", err)
				}
				queue = queue[1:]
			}

			var (
				sendCh chan<- *cryptossh.Request
				next   *cryptossh.Request
			)
			if len(queue) > 0 {
				sendCh = out
				next = queue[0].req
			}

			select {
			case req, ok := <-in:
				if !ok {
					return
				}
				if len(queue) >= maxQueuedRequests {
					log.Warnf("SSH session request queue full, closing channel")
					_ = ch.Close()
					return
				}
				item := &sessionRequest{req: req, forward: true}
				switch req.Type {
				case "pty-req":
					if !validPtyReqPayload(req.Payload) {
						item.forward, item.reply = false, false
					}
				case "env":
					envCount++
					if envCount > maxEnvRequests || len(req.Payload) > maxEnvPayload {
						item.forward, item.reply = false, false
					}
				case "shell", "exec", "subsystem":
					started = true
				case "window-change":
					if !started {
						item.forward, item.reply = false, true
						break
					}
					if lastWinch != nil {
						lastWinch.forward, lastWinch.reply = false, true
					}
					lastWinch = item
				}
				queue = append(queue, item)
			case sendCh <- next:
				if queue[0] == lastWinch {
					lastWinch = nil
				}
				queue = queue[1:]
			}
		}
	}()

	return out
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
