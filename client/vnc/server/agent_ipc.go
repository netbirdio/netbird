//go:build !js && !ios && !android

package server

import (
	crand "crypto/rand"
	"encoding/hex"
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
)

// generateAuthToken returns a fresh hex-encoded random token for one
// daemon→agent session. The daemon hands this to the spawned agent
// out-of-band (env var on Windows) and verifies it on every connection
// the agent accepts. Returns the empty string on a randomness failure;
// callers should treat that as an error.
func generateAuthToken() string {
	b := make([]byte, agentTokenLen)
	if _, err := crand.Read(b); err != nil {
		log.Warnf("generate agent auth token: %v", err)
		return ""
	}
	return hex.EncodeToString(b)
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

	tokenBytes, _ := hex.DecodeString(authToken)
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
