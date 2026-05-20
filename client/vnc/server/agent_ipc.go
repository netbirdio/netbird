//go:build darwin || windows

package server

import (
	"bufio"
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	// agentPort is the TCP loopback port on which a per-session VNC agent
	// listens. The daemon dials this port and presents agentToken before
	// proxying VNC bytes. The choice of TCP (rather than a Unix socket or
	// named pipe) is intentional: it lets the same proxy/handshake code
	// run on every platform; the token does the access control.
	agentPort uint16 = 15900

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

// proxyToAgent dials the per-session agent on TCP loopback, writes the
// raw token bytes, and then copies bytes in both directions until either
// side closes. The token has to land on the wire before any VNC byte so
// the agent's listening Server can apply verifyAgentToken before letting
// real RFB traffic through.
func proxyToAgent(client net.Conn, port uint16, authToken string) {
	defer client.Close()

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	agentConn, err := dialAgentWithRetry(addr)
	if err != nil {
		log.Warnf("proxy cannot reach agent at %s: %v", addr, err)
		return
	}
	defer agentConn.Close()

	tokenBytes, err := hex.DecodeString(authToken)
	if err != nil || len(tokenBytes) != agentTokenLen {
		log.Warnf("invalid auth token (len=%d): %v", len(tokenBytes), err)
		return
	}
	if _, err := agentConn.Write(tokenBytes); err != nil {
		log.Warnf("send auth token to agent: %v", err)
		return
	}

	log.Debugf("proxy connected to agent, starting bidirectional copy")
	done := make(chan struct{}, 2)
	cp := func(label string, dst, src net.Conn) {
		n, err := io.Copy(dst, src)
		log.Debugf("proxy %s: %d bytes, err=%v", label, n, err)
		done <- struct{}{}
	}
	go cp("client→agent", agentConn, client)
	go cp("agent→client", client, agentConn)
	<-done
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
// the final error.
func dialAgentWithRetry(addr string) (net.Conn, error) {
	var lastErr error
	for range 50 {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			return c, nil
		}
		lastErr = err
		time.Sleep(200 * time.Millisecond)
	}
	return nil, lastErr
}
