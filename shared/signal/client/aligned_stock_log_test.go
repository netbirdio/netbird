package client

import (
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"

	nbgrpc "github.com/netbirdio/netbird/client/grpc"
	"github.com/netbirdio/netbird/shared/alignedhb"
	"github.com/netbirdio/netbird/util/wsproxy"
)

// captureInfo collects log entries until the test ends.
func captureInfo(t *testing.T) *logtest.Hook {
	t.Helper()
	hook := logtest.NewGlobal()
	t.Cleanup(func() { log.StandardLogger().ReplaceHooks(make(log.LevelHooks)) })
	return hook
}

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

// The connection kept the stock keepalive of an earlier stock server, and
// an aligned answer cleared the mark without a redial. A server without the
// aligned heartbeat then sends no answer: no redial, the server is marked,
// and one line says the stream runs stock.
func TestSignalStockAnswerAfterAlignedSessionLogs(t *testing.T) {
	c, redials := newSignalRedialClient(t, "signal-082.example:443")
	swapConn(c, lazySignalConn(t), 30*time.Second)
	key := c.key.PublicKey().String()
	nbgrpc.MarkStock(wsproxy.SignalComponent, c.addr)
	header := metadata.Pairs(alignedhb.MetadataKey, alignedhb.PendingAnswerValue(time.Minute))
	c.applyAlignedAnswer(header, &blockingSender{release: make(chan struct{})}, key, 0)
	require.True(t, nbgrpc.MarkStock(wsproxy.SignalComponent, c.addr), "the answer cleared the mark")
	nbgrpc.ClearStock(wsproxy.SignalComponent, c.addr)

	hook := captureInfo(t)
	c.applyAlignedAnswer(metadata.MD{}, &blockingSender{release: make(chan struct{})}, key, 0)
	time.Sleep(50 * time.Millisecond)
	assert.Zero(t, redials.Load(), "a stock keepalive connection must not redial")
	assert.False(t, nbgrpc.MarkStock(wsproxy.SignalComponent, c.addr), "the stock answer marks the server")
	assert.Equal(t, 1, infoLines(hook, "Signal answered stock, the stream runs stock"),
		"the stock answer must leave one line")

	c.applyAlignedAnswer(metadata.MD{}, &blockingSender{release: make(chan struct{})}, key, 0)
	assert.Equal(t, 1, infoLines(hook, "Signal answered stock"), "a marked server logs no second line")
}
