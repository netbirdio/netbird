package client

import (
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbgrpc "github.com/netbirdio/netbird/client/grpc"
	"github.com/netbirdio/netbird/shared/alignedhb"
	"github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/shared/relay/messages"
	"github.com/netbirdio/netbird/util/wsproxy"
)

// infoLines counts the Info entries of hook that contain substr.
func infoLines(hook *logtest.Hook, substr string) int {
	n := 0
	for _, e := range hook.AllEntries() {
		if e.Level == log.InfoLevel && strings.Contains(e.Message, substr) {
			n++
		}
	}
	return n
}

// signedConfig is an aligned answer with a signed phase.
func signedConfig() *proto.AlignedHeartbeatConfig {
	return &proto.AlignedHeartbeatConfig{
		Enabled: true, PeriodSeconds: 60, PhaseMillis: 3107, PhaseDay: 20772, PhaseSignature: []byte{1, 2, 3},
	}
}

// The client redialed with the stock keepalive on an earlier stock server,
// then an aligned server cleared the mark without a redial. A server without
// the aligned heartbeat field then answers stock on that connection: it must
// not redial, the server is marked again, and one line says the stream runs
// stock.
func TestStockAnswerAfterAlignedSessionLogs(t *testing.T) {
	setAlignedRequest(t, time.Minute, true)
	c, redials := newRedialClient(t, "mgmt-082.example:443")
	t.Cleanup(func() { alignedhb.ClearSignedPhase(messages.HashID(c.key.PublicKey().String())) })
	swapConn(c, lazyConn(t), 30*time.Second)
	nbgrpc.MarkStock(wsproxy.ManagementComponent, c.serverURL)
	c.applyAlignedAnswer(&proto.SyncResponse{PeerConfig: &proto.PeerConfig{AlignedHeartbeat: signedConfig()}}, true)
	require.True(t, nbgrpc.MarkStock(wsproxy.ManagementComponent, c.serverURL), "the aligned answer cleared the mark")
	nbgrpc.ClearStock(wsproxy.ManagementComponent, c.serverURL)

	hook := logtest.NewGlobal()
	t.Cleanup(func() { log.StandardLogger().ReplaceHooks(make(log.LevelHooks)) })

	// 0.82.0: a peer config without the field, no heartbeat.
	c.applyAlignedAnswer(stockSync, true)
	time.Sleep(50 * time.Millisecond)
	assert.Zero(t, redials.Load(), "a stock keepalive connection must not redial")
	assert.False(t, nbgrpc.MarkStock(wsproxy.ManagementComponent, c.serverURL), "the stock answer marks the server")
	assert.Equal(t, 1, infoLines(hook, "Management answered stock, the stream runs stock"),
		"the stock answer must leave one line")

	// Later streams on the marked server stay quiet.
	c.applyAlignedAnswer(stockSync, true)
	assert.Equal(t, 1, infoLines(hook, "Management answered stock"), "a marked server logs no second line")
}

// A signed answer is announced once per Sync stream and with each new day's
// phase. Later updates, unsigned answers and clients that did not ask stay
// silent.
func TestSignedAnswerAnnouncedOncePerStream(t *testing.T) {
	setAlignedRequest(t, time.Minute, true)
	c, _ := newRedialClient(t, "mgmt-announce.example:443")
	t.Cleanup(func() { alignedhb.ClearSignedPhase(messages.HashID(c.key.PublicKey().String())) })
	signed := &proto.SyncResponse{PeerConfig: &proto.PeerConfig{AlignedHeartbeat: signedConfig()}}
	announced := func(ch <-chan struct{}) bool {
		select {
		case <-ch:
			return true
		default:
			return false
		}
	}

	ch := alignedhb.SignedAnswerAnnounced()
	c.applyAlignedAnswer(signed, true)
	assert.True(t, announced(ch), "the first signed answer of a stream must be announced")

	ch = alignedhb.SignedAnswerAnnounced()
	c.applyAlignedAnswer(signed, false)
	assert.False(t, announced(ch), "a later update of the same stream must not be announced")

	c.applyAlignedAnswer(signed, true)
	assert.True(t, announced(ch), "the same phase on a new stream must be announced again")

	ch = alignedhb.SignedAnswerAnnounced()
	c.handleHeartbeat(&proto.Heartbeat{Config: signedConfig()})
	assert.True(t, announced(ch), "a new day's phase must be announced")

	ch = alignedhb.SignedAnswerAnnounced()
	c.applyAlignedAnswer(&proto.SyncResponse{PeerConfig: &proto.PeerConfig{
		AlignedHeartbeat: &proto.AlignedHeartbeatConfig{Enabled: true, PeriodSeconds: 60, PhaseMillis: 1000},
	}}, true)
	assert.False(t, announced(ch), "an unsigned answer must not be announced")
	c.applyAlignedAnswer(stockSync, true)
	assert.False(t, announced(ch), "a stock answer must not be announced")

	setAlignedRequest(t, 0, false)
	c.applyAlignedAnswer(signed, true)
	assert.False(t, announced(ch), "a client that did not ask must not announce")
}
