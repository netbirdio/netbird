package client

import (
	"net/netip"
	"runtime"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManager_RelayInstanceAddressAcrossReconnect(t *testing.T) {
	relays := []struct {
		url  *RelayAddr
		conn stubConn
		ip   netip.Addr
	}{
		{
			url:  &RelayAddr{addr: "rels://relay-a.example:443"},
			conn: stubConn{remote: staticAddr{s: "192.0.2.1:443"}},
			ip:   netip.MustParseAddr("192.0.2.1"),
		},
		{
			url:  &RelayAddr{addr: "rels://relay-b.example:443"},
			conn: stubConn{remote: staticAddr{s: "192.0.2.2:443"}},
			ip:   netip.MustParseAddr("192.0.2.2"),
		},
	}
	c := &Client{}
	sessions := make([]*session, 0, len(relays))
	for _, relay := range relays {
		sessions = append(sessions, &session{client: c, instanceURL: relay.url, conn: relay.conn})
	}
	c.session = sessions[0]
	m := &Manager{relayClient: c}
	started := make(chan struct{})
	stop := make(chan struct{})
	done := make(chan struct{})
	t.Cleanup(func() {
		close(stop)
		<-done
	})
	go func() {
		defer close(done)
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			// Publish successive sessions the way a reconnect does. Yield before
			// publication so a getter that read the URL and the IP from two
			// different sessions would pair the old URL with the new IP.
			c.mu.Lock()
			runtime.Gosched()
			c.session = sessions[i%len(sessions)]
			c.mu.Unlock()
			if i == 0 {
				close(started)
			}
		}
	}()
	<-started

	for range 1000 {
		url, ip, err := m.RelayInstanceAddress()
		require.NoError(t, err)
		wantIP := relays[0].ip
		if url == relays[1].url.String() {
			wantIP = relays[1].ip
		}
		if !assert.Equal(t, wantIP, ip, "advertised IP must belong to relay %s", url) {
			return
		}
	}
}

func TestManager_RelayInstanceAddressDisconnected(t *testing.T) {
	closed := &Client{}
	s := &session{
		client:      closed,
		log:         log.WithField("test", t.Name()),
		conn:        &closeTrackingConn{},
		instanceURL: &RelayAddr{addr: "rels://relay-a.example:443"},
		earlyMsgs:   newEarlyMsgBuffer(),
	}
	closed.session = s
	require.NoError(t, s.Close(false))

	for _, tt := range []struct {
		name   string
		client *Client
	}{
		{name: "no client"},
		{name: "not connected", client: &Client{}},
		{name: "closed connection", client: closed},
	} {
		t.Run(tt.name, func(t *testing.T) {
			m := &Manager{relayClient: tt.client}
			url, ip, err := m.RelayInstanceAddress()
			assert.Error(t, err)
			assert.Empty(t, url, "disconnected relay must not advertise a URL")
			assert.False(t, ip.IsValid(), "disconnected relay must not advertise a stale IP")
		})
	}
}
