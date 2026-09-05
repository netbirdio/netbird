//go:build !js && !ios && !android

package server

import (
	"bytes"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runHandshake drives both halves over an in-memory pipe and returns what each
// side concluded.
func runHandshake(t *testing.T, daemonToken, agentToken []byte, viewOnly bool) (daemonErr error, gotViewOnly bool, agentErr error) {
	t.Helper()

	daemonSide, agentSide := net.Pipe()
	t.Cleanup(func() {
		_ = daemonSide.Close()
		_ = agentSide.Close()
	})

	type agentResult struct {
		viewOnly bool
		err      error
	}
	agentDone := make(chan agentResult, 1)
	go func() {
		v, err := agentServerHandshake(agentSide, agentToken)
		if err != nil {
			// What the agent's caller does on rejection, so the daemon sees the
			// close rather than waiting out its own deadline.
			_ = agentSide.Close()
		}
		agentDone <- agentResult{v, err}
	}()

	daemonErr = agentClientHandshake(daemonSide, daemonToken, viewOnly)
	res := <-agentDone
	return daemonErr, res.viewOnly, res.err
}

func TestAgentHandshake_MatchingTokens(t *testing.T) {
	token := bytes.Repeat([]byte{0xA5}, agentTokenLen)

	for _, viewOnly := range []bool{false, true} {
		dErr, gotViewOnly, aErr := runHandshake(t, token, token, viewOnly)
		require.NoError(t, dErr)
		require.NoError(t, aErr)
		assert.Equal(t, viewOnly, gotViewOnly, "the agent must see the flag the daemon authenticated")
	}
}

// The point of the exchange: an impostor listening on the socket without the
// token cannot complete it, and the daemon refuses before proxying anything.
func TestAgentHandshake_ImpostorAgentIsRefused(t *testing.T) {
	daemonToken := bytes.Repeat([]byte{0x01}, agentTokenLen)
	impostorToken := bytes.Repeat([]byte{0x02}, agentTokenLen)

	dErr, _, aErr := runHandshake(t, daemonToken, impostorToken, false)
	require.Error(t, aErr, "the impostor cannot verify the daemon's tag")
	require.Error(t, dErr, "the daemon must not proceed against an unproven peer")
}

// And the other direction: something dialling the agent without the token gets
// nowhere either.
func TestAgentHandshake_ImpostorDaemonIsRefused(t *testing.T) {
	agentToken := bytes.Repeat([]byte{0x03}, agentTokenLen)
	impostorToken := bytes.Repeat([]byte{0x04}, agentTokenLen)

	_, _, aErr := runHandshake(t, impostorToken, agentToken, false)
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

	// Tee everything the daemon writes so it can be searched afterwards.
	var sent bytes.Buffer
	go func() {
		_, _ = agentServerHandshake(&teeConn{Conn: agentSide, read: &sent}, token)
	}()

	require.NoError(t, agentClientHandshake(daemonSide, token, false))
	assert.NotContains(t, sent.Bytes(), token, "the token must not cross the socket")
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

// teeConn records everything read from the wrapped connection.
type teeConn struct {
	net.Conn
	read *bytes.Buffer
}

func (c *teeConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.read.Write(b[:n])
	}
	return n, err
}
