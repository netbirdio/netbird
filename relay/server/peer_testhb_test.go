package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/relay/server/listener/ws"
	"github.com/netbirdio/netbird/shared/relay/messages"
	"github.com/netbirdio/netbird/shared/testhb"
)

type testHBConn struct {
	closeRecorderConn
	cs testhb.ClientSchedule
}

func (c *testHBConn) TestHBSchedule() testhb.ClientSchedule { return c.cs }

var _ interface{ TestHBSchedule() testhb.ClientSchedule } = (*ws.Conn)(nil)

func TestPeerTestHBSchedule(t *testing.T) {
	cs := testhb.ClientSchedule{PhaseMs: 1234, Period: 30 * time.Second, SkewMs: -5, OK: true}
	p := NewPeer(nil, messages.HashID("alice"), messages.ProtocolV1, &testHBConn{cs: cs}, nil, nil)
	assert.Equal(t, cs, p.testHBSchedule(), "peer must read the schedule from its conn")

	p = NewPeer(nil, messages.HashID("bob"), messages.ProtocolV1, &closeRecorderConn{}, nil, nil)
	assert.False(t, p.testHBSchedule().OK, "a conn without a schedule gives none")
}
