//go:build darwin || windows

package server

import (
	"bufio"
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	log "github.com/sirupsen/logrus"
)

// errNoConsoleUser is the sentinel returned by sessionAgent.Resolve when
// the platform has no interactive user to attach a capture agent to (the
// macOS loginwindow state). Mapped to a distinct RFB reject code so the
// browser can show a meaningful message.
var errNoConsoleUser = errors.New("no user logged into console")

// sessionAgent abstracts the per-platform manager that spawns and tracks
// the user-session VNC agent. Resolve returns the agent's Unix-socket
// path, the shared per-spawn token, and the uid the agent was spawned
// under (used to validate peer credentials before the daemon hands the
// token to whoever is on the other end of the socket). Resolve may spawn
// the agent lazily.
type sessionAgent interface {
	Resolve(ctx context.Context) (socketPath, token string, peerUID uint32, err error)
}

// prefixConn replays already-consumed header bytes ahead of the proxy
// stream by swapping in a different Reader on the same underlying Conn.
type prefixConn struct {
	io.Reader
	net.Conn
}

func (p *prefixConn) Read(b []byte) (int, error) { return p.Reader.Read(b) }

// handleServiceConnection runs the connection-header handshake (source
// check, Noise_IK auth) on conn, resolves the right per-session agent
// via sa, and proxies to it. Every accepted connection emits exactly one
// outcome line on the daemon log.
func (s *Server) handleServiceConnection(conn net.Conn, sa sessionAgent) {
	start := time.Now()
	connLog := s.log.WithField("remote", conn.RemoteAddr().String())

	if !s.isAllowedSource(conn.RemoteAddr()) {
		connLog.Info("VNC connection rejected: source not allowed")
		_ = conn.Close()
		return
	}

	var headerBuf bytes.Buffer
	tee := io.TeeReader(conn, &headerBuf)
	teeConn := &prefixConn{Reader: tee, Conn: conn}

	header, err := s.readConnectionHeader(teeConn)
	if err != nil {
		connLog.Infof("VNC connection rejected: header read failed: %v", err)
		_ = conn.Close()
		return
	}

	authedLog, sessionUserID, ok := s.authorizeSession(conn, header, connLog)
	if !ok {
		authedLog.Info("VNC connection rejected: auth failed")
		return
	}
	if err := s.registerConnAuth(conn, header); err != nil {
		rejectConnection(conn, codeMessage(RejectCodeAuthForbidden, err.Error()))
		authedLog.Warnf("VNC connection rejected: %v", err)
		return
	}

	decision, err := s.gateApproval(conn, header)
	if err != nil {
		authedLog.Infof("VNC connection rejected: %v", err)
		return
	}
	if decision.ViewOnly {
		authedLog.Info("VNC connection approved by user (view-only)")
	} else if s.requireApproval {
		authedLog.Info("VNC connection approved by user")
	}

	socketPath, token, peerUID, err := sa.Resolve(s.ctx)
	if err != nil {
		code := RejectCodeCapturerError
		if errors.Is(err, errNoConsoleUser) {
			code = RejectCodeNoConsoleUser
		}
		rejectConnection(conn, codeMessage(code, err.Error()))
		authedLog.Warnf("VNC connection rejected: agent unavailable: %v", err)
		return
	}

	var initiator string
	if s.authorizer != nil {
		initiator = s.authorizer.LookupSessionDisplayName(header.clientStatic)
	}
	sessionID := s.addSession(ActiveSessionInfo{
		RemoteAddress: conn.RemoteAddr().String(),
		Mode:          modeString(header.mode),
		Username:      header.username,
		UserID:        sessionUserID,
		Initiator:     initiator,
	}, conn)
	defer s.removeSession(sessionID)

	replayConn := &prefixConn{
		Reader: io.MultiReader(&headerBuf, conn),
		Conn:   conn,
	}
	if err := proxyToAgent(s.ctx, replayConn, socketPath, token, peerUID, decision.ViewOnly, authedLog); err != nil {
		rejectConnection(conn, codeMessage(RejectCodeCapturerError, err.Error()))
		authedLog.Warnf("VNC connection rejected: agent unreachable: %v", err)
		return
	}
	authedLog.Infof("VNC connection closed (%dms)", time.Since(start).Milliseconds())
}

const (
	// agentTokenLen is the size of the random per-spawn token in bytes.
	agentTokenLen = 32

	// agentTokenEnvVar names the environment variable the daemon uses to
	// hand the per-spawn token to the agent child. Out-of-band channels
	// like this keep the secret out of the command line, where listings
	// such as `ps` or Windows tasklist would expose it.
	agentTokenEnvVar = "NB_VNC_AGENT_TOKEN" // #nosec G101 -- env var name, not a credential

	// vncAgentSubcommand is the CLI subcommand the daemon invokes to start
	// the per-session agent process. Must match cmd.vncAgentCmd.Use in
	// client/cmd/vnc_agent.go.
	vncAgentSubcommand = "vnc-agent"
)

// generateAuthToken returns a fresh hex-encoded random token for one
// daemon→agent session. The daemon hands this to the spawned agent
// out-of-band (env var on Windows) and verifies it on every connection
// the agent accepts.
func generateAuthToken() (string, error) {
	b := make([]byte, agentTokenLen)
	if _, err := crand.Read(b); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// proxyToAgent dials the per-session agent's Unix socket, validates the
// peer's kernel-asserted uid (so the daemon never hands its per-spawn
// token to an impostor that won the listen race), writes the raw token
// bytes plus a single view-only flag byte, then copies bytes both ways
// until either side closes. The token + flag prefix must precede any RFB
// byte so the agent's verifyAgentToken can run first. Returns nil once a
// stream is established; the caller is responsible for sending an
// RFB-level rejection on error so the client sees a reason instead of a
// bare timeout. authedLog receives one audit line per dispatched
// preamble so an operator can correlate daemon→agent traffic with the
// remote session that triggered it.
func proxyToAgent(ctx context.Context, client net.Conn, socketPath, authToken string, peerUID uint32, viewOnly bool, authedLog *log.Entry) error {
	tokenBytes, err := hex.DecodeString(authToken)
	if err != nil || len(tokenBytes) != agentTokenLen {
		return fmt.Errorf("invalid auth token (len=%d): %w", len(tokenBytes), err)
	}

	agentConn, err := dialAgentWithRetry(ctx, socketPath)
	if err != nil {
		return fmt.Errorf("dial agent at %s: %w", socketPath, err)
	}

	if err := validateAgentPeer(agentConn, peerUID); err != nil {
		_ = agentConn.Close()
		return fmt.Errorf("agent peer validation failed: %w", err)
	}

	preamble := make([]byte, len(tokenBytes)+1)
	copy(preamble, tokenBytes)
	if viewOnly {
		preamble[len(tokenBytes)] = 1
	}
	if _, err := agentConn.Write(preamble); err != nil {
		_ = agentConn.Close()
		return fmt.Errorf("send auth preamble to agent: %w", err)
	}

	// Audit: one line per successfully-dispatched daemon→agent preamble.
	// Token printed as its first 8 hex chars (enough to correlate, not
	// enough to use). Kept at Info so the default deployment captures it.
	tokenFp := authToken
	if len(tokenFp) > 8 {
		tokenFp = tokenFp[:8]
	}
	if authedLog != nil {
		authedLog.Infof("VNC IPC: dispatched preamble to agent socket=%s peer_uid=%d view_only=%v token_fp=%s", socketPath, peerUID, viewOnly, tokenFp)
	}

	defer client.Close()
	defer agentConn.Close()
	log.Debugf("proxy connected to agent, starting bidirectional copy")
	done := make(chan struct{}, 2)
	cp := func(label string, dst, src net.Conn) {
		n, err := io.Copy(dst, src)
		log.Debugf("proxy %s: %d bytes, err=%v", label, n, err)
		done <- struct{}{}
	}
	go cp("client->agent", agentConn, client)
	go cp("agent->client", client, agentConn)
	<-done
	return nil
}

// relogAgentStream reads log lines from the agent's stderr and re-emits
// them through the daemon's logrus, so the merged log keeps a single
// format. JSON lines (the agent's normal output) are parsed and dispatched
// by level; plain-text lines (cobra errors, panic traces) are forwarded
// verbatim so early-startup failures stay visible.
func relogAgentStream(r io.Reader) {
	entry := log.WithField("component", "vnc-agent")
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		if line[0] != '{' {
			entry.Warn(string(line))
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			entry.Warn(string(line))
			continue
		}
		msg, _ := m["msg"].(string)
		if msg == "" {
			continue
		}
		fields := make(log.Fields)
		for k, v := range m {
			switch k {
			case "msg", "level", "time", "func":
				continue
			case "caller":
				fields["source"] = v
			default:
				fields[k] = v
			}
		}
		e := entry.WithFields(fields)
		switch m["level"] {
		case "error":
			e.Error(msg)
		case "warning":
			e.Warn(msg)
		case "debug":
			e.Debug(msg)
		case "trace":
			e.Trace(msg)
		default:
			e.Info(msg)
		}
	}
}

// dialAgentWithRetry retries the loopback connect for up to ~10 s so the
// daemon does not race the agent's first listen. Returns the live conn or
// the final error. Aborts early when ctx is cancelled so a Stop() during
// service-mode startup doesn't leave a goroutine sleeping for 10 s.
func dialAgentWithRetry(ctx context.Context, addr string) (net.Conn, error) {
	var d net.Dialer
	var lastErr error
	for range 50 {
		if err := ctx.Err(); err != nil {
			if lastErr == nil {
				lastErr = err
			}
			return nil, lastErr
		}
		dialCtx, cancel := context.WithTimeout(ctx, time.Second)
		c, err := d.DialContext(dialCtx, "unix", addr)
		cancel()
		if err == nil {
			return c, nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
			if errors.Is(lastErr, context.Canceled) || errors.Is(lastErr, context.DeadlineExceeded) {
				lastErr = ctx.Err()
			}
			return nil, lastErr
		case <-time.After(200 * time.Millisecond):
		}
	}
	return nil, lastErr
}
