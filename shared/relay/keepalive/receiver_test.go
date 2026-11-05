package keepalive

import (
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestReceiverRequestReadBeforeExpiryHandlingKeepsConnection(t *testing.T) {
	r := newReceiver(log.NewEntry(log.New()))
	timer := newStoppedTimer()

	r.Refresh()
	time.Sleep(50 * time.Millisecond)

	require.False(t, r.handleExpiry(timer))
	select {
	case <-r.OnTimeout:
		t.Fatal("unexpected keepalive timeout")
	default:
	}
}

func TestReceiverExpiryWithoutRequestCloses(t *testing.T) {
	r := newReceiver(log.NewEntry(log.New()))
	timer := newStoppedTimer()

	require.True(t, r.handleExpiry(timer))
	select {
	case <-r.OnTimeout:
	default:
		t.Fatal("expected keepalive timeout")
	}
}

func TestReceiverRepeatedExpiryAfterSingleRequestCloses(t *testing.T) {
	r := newReceiver(log.NewEntry(log.New()))
	timer := newStoppedTimer()

	r.Refresh()
	require.False(t, r.handleExpiry(timer))
	require.True(t, r.handleExpiry(timer))
}
