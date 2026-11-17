package client

import (
	"net/netip"
	"runtime"
	"testing"

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
	c := &Client{
		instanceURL:      relays[0].url,
		relayConn:        relays[0].conn,
		serviceIsRunning: true,
	}
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
			// Publish successive connection states using the lifecycle locks.
			// Yield before publication so a getter using only muInstanceURL
			// can read the old URL while waiting for the new connection's IP.
			c.mu.Lock()
			runtime.Gosched()
			relay := relays[i%len(relays)]
			c.muInstanceURL.Lock()
			c.instanceURL = relay.url
			c.muInstanceURL.Unlock()
			c.relayConn = relay.conn
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
	for _, tt := range []struct {
		name   string
		client *Client
	}{
		{name: "no client"},
		{name: "not connected", client: &Client{}},
		{
			name: "closed connection",
			client: &Client{
				relayConn: stubConn{remote: staticAddr{s: "192.0.2.1:443"}},
			},
		},
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
