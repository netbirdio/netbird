//go:build !js && !ios && !android

package server

import (
	"bytes"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runHandshake drives both halves over an in-memory pipe and returns what each
// side concluded.
func runHandshake(t *testing.T, daemonToken, agentToken []byte, grant agentGrant) (daemonErr error, got agentGrant, agentErr error) {
	t.Helper()
	return runHandshakeOver(t, daemonToken, agentToken, grant, func(c net.Conn) net.Conn { return c })
}

// runHandshakeOver is runHandshake with the daemon's end of the connection
// wrapped, so a test can interfere with what the daemon sends.
func runHandshakeOver(t *testing.T, daemonToken, agentToken []byte, grant agentGrant, wrap func(net.Conn) net.Conn) (daemonErr error, got agentGrant, agentErr error) {
	t.Helper()

	daemonSide, agentSide := net.Pipe()
	t.Cleanup(func() {
		_ = daemonSide.Close()
		_ = agentSide.Close()
	})

	type agentResult struct {
		grant agentGrant
		err   error
	}
	agentDone := make(chan agentResult, 1)
	go func() {
		g, err := agentServerHandshake(agentSide, agentToken)
		if err != nil {
			// What the agent's caller does on rejection, so the daemon sees the
			// close rather than waiting out its own deadline.
			_ = agentSide.Close()
		}
		agentDone <- agentResult{g, err}
	}()

	daemonErr = agentClientHandshake(wrap(daemonSide), daemonToken, grant)
	res := <-agentDone
	return daemonErr, res.grant, res.err
}

func TestAgentHandshake_MatchingTokens(t *testing.T) {
	token := bytes.Repeat([]byte{0xA5}, agentTokenLen)

	for _, grant := range []agentGrant{
		{viewOnly: false, peerAddr: "100.64.0.7:51234"},
		{viewOnly: true, peerAddr: "[fd00:1234::2]:5900"},
		{viewOnly: false, peerAddr: ""},
	} {
		dErr, got, aErr := runHandshake(t, token, token, grant)
		require.NoError(t, dErr)
		require.NoError(t, aErr)
		assert.Equal(t, grant, got, "the agent must see the grant the daemon authenticated")
	}
}

// The peer address is covered by the daemon's tag, so rewriting it in flight
// fails the handshake instead of misattributing the session.
func TestAgentHandshake_TamperedPeerAddrIsRefused(t *testing.T) {
	token := bytes.Repeat([]byte{0x5A}, agentTokenLen)
	grant := agentGrant{peerAddr: "100.64.0.7:51234"}

	_, _, aErr := runHandshakeOver(t, token, token, grant, func(c net.Conn) net.Conn {
		return &rewriteConn{Conn: c, from: []byte("100.64.0.7"), to: []byte("100.64.0.9")}
	})
	require.Error(t, aErr)
	assert.Contains(t, aErr.Error(), "did not prove it holds the session token")
}

func TestAgentHandshake_OversizedPeerAddrIsRefused(t *testing.T) {
	token := bytes.Repeat([]byte{0x6B}, agentTokenLen)
	daemonSide, agentSide := net.Pipe()
	defer daemonSide.Close()
	defer agentSide.Close()

	err := agentClientHandshake(daemonSide, token, agentGrant{peerAddr: string(bytes.Repeat([]byte{'a'}, maxAgentPeerAddrLen+1))})
	require.Error(t, err, "an address longer than the length byte can carry must not be truncated silently")
}

// The point of the exchange: an impostor listening on the socket without the
// token cannot complete it, and the daemon refuses before proxying anything.
func TestAgentHandshake_ImpostorAgentIsRefused(t *testing.T) {
	daemonToken := bytes.Repeat([]byte{0x01}, agentTokenLen)
	impostorToken := bytes.Repeat([]byte{0x02}, agentTokenLen)

	dErr, _, aErr := runHandshake(t, daemonToken, impostorToken, agentGrant{})
	require.Error(t, aErr, "the impostor cannot verify the daemon's tag")
	require.Error(t, dErr, "the daemon must not proceed against an unproven peer")
}

// And the other direction: something dialling the agent without the token gets
// nowhere either.
func TestAgentHandshake_ImpostorDaemonIsRefused(t *testing.T) {
	agentToken := bytes.Repeat([]byte{0x03}, agentTokenLen)
	impostorToken := bytes.Repeat([]byte{0x04}, agentTokenLen)

	_, _, aErr := runHandshake(t, impostorToken, agentToken, agentGrant{})
	require.Error(t, aErr)
	assert.Contains(t, aErr.Error(), "did not prove it holds the session token")
}

// The token itself must never appear on the wire; that was the whole reason for
// replacing the plain preamble.
func TestAgentHandshake_TokenNeverSent(t *testing.T) {
	token := bytes.Repeat([]byte{0x7E}, agentTokenLen)

	daemonSide, agentSide := net.Pipe()
	defer daemonSide.Close()
	defer agentSide.Close()

	// Tee both directions on the agent's end: what it reads is everything the
	// daemon sent, what it writes is its challenge and reply. Either side
	// leaking the token is the failure this test is for.
	var wire bytes.Buffer
	var mu sync.Mutex
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = agentServerHandshake(&teeConn{Conn: agentSide, mu: &mu, read: &wire, written: &wire}, token)
	}()

	require.NoError(t, agentClientHandshake(daemonSide, token, agentGrant{}))
	<-done
	mu.Lock()
	defer mu.Unlock()
	// bytes.Contains, not assert.NotContains: testify compares a []byte
	// haystack element-wise, and a []byte is never an element of a []byte, so
	// the assertion held whatever crossed the wire — including the whole token.
	assert.False(t, bytes.Contains(wire.Bytes(), token), "the token must not cross the socket")
}

// A tag is bound to the nonce it answered, so replaying one against a fresh
// challenge fails.
func TestAgentMAC_IsBoundToNonceAndLabel(t *testing.T) {
	token := bytes.Repeat([]byte{0x11}, agentTokenLen)
	nonceA := bytes.Repeat([]byte{0x22}, agentNonceLen)
	nonceB := bytes.Repeat([]byte{0x33}, agentNonceLen)

	assert.NotEqual(t,
		agentMAC(token, agentDaemonLabel, nonceA),
		agentMAC(token, agentDaemonLabel, nonceB),
		"a different challenge must produce a different tag")

	assert.NotEqual(t,
		agentMAC(token, agentDaemonLabel, nonceA),
		agentMAC(token, agentAgentLabel, nonceA),
		"the two directions must not share a tag, or one could be replayed as the other")
}

// teeConn records every byte read from and written to the wrapped connection.
type teeConn struct {
	net.Conn
	mu      *sync.Mutex
	read    *bytes.Buffer
	written *bytes.Buffer
}

func (c *teeConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 && c.read != nil {
		c.mu.Lock()
		c.read.Write(b[:n])
		c.mu.Unlock()
	}
	return n, err
}

func (c *teeConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 && c.written != nil {
		c.mu.Lock()
		c.written.Write(b[:n])
		c.mu.Unlock()
	}
	return n, err
}

// rewriteConn replaces the first occurrence of from with to in what is written,
// standing in for something on the socket altering the daemon's bytes.
type rewriteConn struct {
	net.Conn
	from, to []byte
}

func (c *rewriteConn) Write(b []byte) (int, error) {
	return c.Conn.Write(bytes.Replace(b, c.from, c.to, 1))
}
