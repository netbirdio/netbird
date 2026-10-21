package udpmux

import (
	"net"
	"testing"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/stun/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRouting_DuplicateResponsePreservesCandidate(t *testing.T) {
	lab := newNATLab(t)
	host := lab.addNATedHost(t)
	conn, err := host.net.ListenPacket("udp4", "0.0.0.0:51820")
	require.NoError(t, err)
	mux := startMux(t, UniversalUDPMuxParams{UDPConn: conn, Net: host.net, MTU: 1280})
	trace := newSTUNTrace()
	hostMux := &candidateHostMux{UDPMux: mux.SingleSocketUDPMux, trace: trace, groups: make(map[net.PacketConn]*candidateReadGroup)}
	agent, err := ice.NewAgent(&ice.AgentConfig{
		NetworkTypes:     []ice.NetworkType{ice.NetworkTypeUDP4},
		CandidateTypes:   []ice.CandidateType{ice.CandidateTypeHost, ice.CandidateTypeServerReflexive},
		Urls:             []*stun.URI{lab.stunURL},
		UDPMux:           &delayedSuccessHostMux{UDPMux: hostMux},
		UDPMuxSrflx:      &candidateSrflxMux{UniversalUDPMux: mux, trace: trace},
		Net:              host.net,
		MulticastDNSMode: ice.MulticastDNSModeDisabled,
		LoggerFactory:    quietLoggerFactory(),
	})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, agent.Close()) })

	peerNet := lab.addNATedHost(t)
	peerConn, err := peerNet.net.ListenPacket("udp4", peerNet.ip+":51820")
	require.NoError(t, err)
	peerMux := startMux(t, UniversalUDPMuxParams{
		UDPConn: &duplicateBindingSuccessConn{PacketConn: &pairIDStrippingConn{PacketConn: peerConn}},
		Net:     peerNet.net,
		MTU:     1280,
	})
	peerHost := &muxHost{lab: lab, net: peerNet.net, mux: peerMux, trace: newSTUNTrace()}
	peer := peerHost.newAgent(t)
	lab.start(t)
	localCandidates, peerCandidates := gather(t, agent), gather(t, peer)
	require.Len(t, localCandidates, 3, "physical host, loopback host and STUN-derived srflx must all exist")
	hostMux.activate()
	connectCandidateAgents(t, agent, peer, localCandidates, peerCandidates, false)

	// Wait for both copies from every answered check, including the delayed
	// host reads, so a late duplicate cannot escape the ownership assertions.
	require.Eventually(t, func() bool {
		peerHost.trace.mu.Lock()
		defer peerHost.trace.mu.Unlock()
		trace.mu.Lock()
		defer trace.mu.Unlock()
		for id := range peerHost.trace.responseWriters {
			if len(trace.responseReaders[id]) < 2 {
				return false
			}
		}
		return len(peerHost.trace.responseWriters) > 0
	}, time.Second, 10*time.Millisecond, "every duplicated success must reach a candidate reader")

	trace.mu.Lock()
	for id, readers := range trace.responseReaders {
		writers := trace.requestWriters[id]
		if assert.NotEmpty(t, writers, "response %x must have an originating candidate", id[:4]) {
			assert.Len(t, readers, 2, "response %x must deliver its two copies without broadcasting", id[:4])
			for _, reader := range readers {
				assert.Equal(t, writers[len(writers)-1], reader, "duplicate response %x must retain its requesting candidate", id[:4])
			}
		}
	}
	trace.mu.Unlock()
	assert.Empty(t, trace.report().misdeliveredRequests)
	assertRouting(t, "peer without pair ID", peerHost)
}

type delayedSuccessHostMux struct {
	ice.UDPMux
}

func (m *delayedSuccessHostMux) GetConn(ufrag string, addr net.Addr, candidateID string) (net.PacketConn, error) {
	conn, err := m.UDPMux.GetConn(ufrag, addr, candidateID)
	if err != nil {
		return nil, err
	}
	return &delayedSuccessReadConn{PacketConn: conn}, nil
}

type delayedSuccessReadConn struct {
	net.PacketConn
}

func (c *delayedSuccessReadConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if err == nil {
		msg := &stun.Message{Raw: b[:n]}
		if msg.Decode() == nil && msg.Type == stun.BindingSuccess {
			// A different candidate can process a broadcast duplicate while the
			// original sender's reader is descheduled. No packet is discarded.
			time.Sleep(30 * time.Millisecond)
		}
	}
	return n, addr, err
}

type duplicateBindingSuccessConn struct {
	net.PacketConn
}

func (c *duplicateBindingSuccessConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	n, err := c.PacketConn.WriteTo(b, addr)
	if err != nil {
		return n, err
	}
	msg := &stun.Message{Raw: b}
	if msg.Decode() == nil && msg.Type == stun.BindingSuccess {
		// Older muxes deliver one request to both host and srflx readers,
		// producing these two equivalent responses on the wire.
		_, err = c.PacketConn.WriteTo(b, addr)
	}
	return n, err
}
