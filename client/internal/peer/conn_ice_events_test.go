package peer

import (
	"context"
	"net"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/peer/worker"
)

type iceEventConn struct {
	net.Conn
	closed bool
}

func (c *iceEventConn) Close() error {
	c.closed = true
	return c.Conn.Close()
}

func TestConn_DiscardedICEDialResultClosesConnection(t *testing.T) {
	for _, reason := range []string{"cancelled conn", "shutdown queue", "shutdown batch"} {
		t.Run(reason, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(cancel)
			conn := &Conn{ctx: ctx, Log: log.WithField("test", t.Name())}
			client, server := net.Pipe()
			t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
			remote := &iceEventConn{Conn: client}
			e := worker.ICEDialDone{Conn: remote}
			mb := newMailbox()
			switch reason {
			case "cancelled conn":
				cancel()
				conn.handleEvent(e)
			case "shutdown queue":
				require.True(t, mb.post(e), "the result must enter the queue before shutdown")
				conn.releaseEvents(mb.closeAndDrain())
			case "shutdown batch":
				require.True(t, mb.post(e), "the result must enter the batch before shutdown")
				conn.releaseEvents(mb.drain())
			}
			assert.True(t, remote.closed, "discarded results must release their connections")
		})
	}
}
