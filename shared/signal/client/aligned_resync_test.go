package client

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	nbgrpc "github.com/netbirdio/netbird/client/grpc"
	"github.com/netbirdio/netbird/shared/alignedhb"
	"github.com/netbirdio/netbird/util/wsproxy"
)

const reopenLine = "Management answered aligned while the Signal stream runs stock, reopening it"

// The server went from a stock build back to a build with the aligned
// heartbeat behind a proxy that kept the stock stream open. Management
// answers aligned, and the Signal stream reopens once and opens aligned. A
// second answer on the aligned stream changes nothing.
func TestSignalStockStreamReopensOnAlignedAnswer(t *testing.T) {
	setAlignedRequest(t, 60*time.Second, true)
	hook := captureInfo(t)
	srv := newRecordingSignalServer(t, true)
	key, err := wgtypes.GenerateKey()
	require.NoError(t, err)
	sp := storeTestSignedPhase(t, key, 60*time.Second)
	client := connectAlignedTestClientWithKey(t, srv, key)
	_, ok := client.alignedHeartbeat()
	require.False(t, ok, "the stream opens stock")
	require.Equal(t, 1, srv.streams())

	srv.stripAnswer.Store(false)
	alignedhb.AnnounceSignedAnswer()
	require.Eventually(t, func() bool {
		_, ok := client.alignedHeartbeat()
		return ok
	}, 10*time.Second, 20*time.Millisecond, "the reopened stream must open aligned")
	got, _ := client.alignedHeartbeat()
	assert.Equal(t, alignedhb.Answer{Period: 60 * time.Second, Phase: sp.Phase}, got, "Signal ticks on the signed phase")
	assert.Equal(t, 2, srv.streams(), "one reopen for the answer")

	alignedhb.AnnounceSignedAnswer()
	time.Sleep(500 * time.Millisecond)
	assert.Equal(t, 2, srv.streams(), "an aligned stream must not reopen")
	assert.Equal(t, 1, infoLines(hook, reopenLine), "one reopen line")
}

// A Signal server that stays stock while Management answers aligned again and
// again, as after every Management reconnect and on the day change. The first
// answer reopens the stock stream once. The reopened stream finds the server
// marked stock and stays on later answers.
func TestSignalStockServerReopensOnce(t *testing.T) {
	setAlignedRequest(t, 60*time.Second, true)
	hook := captureInfo(t)
	srv := newRecordingSignalServer(t, true)
	key, err := wgtypes.GenerateKey()
	require.NoError(t, err)
	storeTestSignedPhase(t, key, 60*time.Second)
	client := connectAlignedTestClientWithKey(t, srv, key)
	t.Cleanup(func() { nbgrpc.ClearStock(wsproxy.SignalComponent, client.addr) })
	require.Equal(t, 1, srv.streams())

	alignedhb.AnnounceSignedAnswer()
	require.Eventually(t, func() bool { return srv.streams() == 2 }, 10*time.Second, 20*time.Millisecond,
		"the first answer must reopen the stock stream")

	for i := 0; i < 3; i++ {
		time.Sleep(300 * time.Millisecond)
		alignedhb.AnnounceSignedAnswer()
	}
	time.Sleep(time.Second)
	assert.Equal(t, 2, srv.streams(), "later answers must not reopen a stream on a server that stays stock")
	assert.Equal(t, 1, infoLines(hook, reopenLine), "one reopen line")
	_, ok := client.alignedHeartbeat()
	assert.False(t, ok, "the stock server keeps the stream stock")
}

// A desktop client does not ask, so a Management answer never reopens its
// stream.
func TestSignalNoReopenWithoutRequest(t *testing.T) {
	setAlignedRequest(t, 0, false)
	srv := newRecordingSignalServer(t, true)
	connectAlignedTestClient(t, srv)

	alignedhb.AnnounceSignedAnswer()
	time.Sleep(500 * time.Millisecond)
	assert.Equal(t, 1, srv.streams(), "a client that does not ask must not reopen")
}
