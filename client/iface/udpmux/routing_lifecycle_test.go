package udpmux

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/stun/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRouting_MixedPairIDRoles(t *testing.T) {
	for _, stripControlling := range []bool{false, true} {
		t.Run(fmt.Sprintf("controlling_without_pair_id=%t", stripControlling), func(t *testing.T) {
			lab := newNATLab(t)
			a := newMuxHost(t, lab, lab.addNATedHost(t), stripControlling)
			b := newMuxHost(t, lab, lab.addNATedHost(t), !stripControlling)
			lab.start(t)
			pair := agentPair{controlling: a.newAgent(t), controlled: b.newAgent(t)}
			connect(t, []agentPair{pair})
			t.Logf("selected pair (local/remote): controlling %s, controlled %s",
				selectedTypes(t, pair.controlling), selectedTypes(t, pair.controlled))
			assertRouting(t, "controlling host", a)
			assertRouting(t, "controlled host", b)
		})
	}
}

func TestRouting_NominationBeforeFirstResponse(t *testing.T) {
	for _, stripControlled := range []bool{false, true} {
		t.Run(fmt.Sprintf("controlled_without_pair_id=%t", stripControlled), func(t *testing.T) {
			lab := newNATLab(t)
			a := newMuxHost(t, lab, lab.addNATedHost(t), true)
			b, gate := newNominationOrderingHost(t, lab, lab.addNATedHost(t), stripControlled)
			lab.start(t)
			connect(t, []agentPair{{controlling: a.newAgent(t), controlled: b.newAgent(t)}})
			gate.mu.Lock()
			assert.True(t, gate.released, "handling nomination must release the held responses")
			assert.Positive(t, gate.heldCount, "at least one check response must arrive before nomination is handled")
			gate.mu.Unlock()
			assertRouting(t, "controlling host", a)
			assertRouting(t, "controlled host", b)
		})
	}
}

func TestRouting_RemoveOldAgentWhileReplacementChecks(t *testing.T) {
	for _, mode := range pairIDModes {
		t.Run(mode.name, func(t *testing.T) {
			lab := newNATLab(t)
			a := newMuxHost(t, lab, lab.addNATedHost(t), mode.strip)
			b := newMuxHost(t, lab, lab.addNATedHost(t), mode.strip)
			lab.start(t)
			old := agentPair{controlling: a.newAgent(t), controlled: b.newAgent(t)}
			live := agentPair{controlling: newKeepaliveAgent(t, a), controlled: newKeepaliveAgent(t, b)}
			connect(t, []agentPair{old, live})
			oldUfrags := make([]string, 2)
			for side, host := range []*muxHost{a, b} {
				assertRouting(t, fmt.Sprintf("host %d before removal", side), host)
				ufrag, _, err := []*ice.Agent{old.controlling, old.controlled}[side].GetLocalUserCredentials()
				require.NoError(t, err)
				oldUfrags[side] = ufrag
			}
			require.NoError(t, old.controlling.Close())
			require.NoError(t, old.controlled.Close())

			for side, host := range []*muxHost{a, b} {
				agent := []*ice.Agent{live.controlling, live.controlled}[side]
				ufrag, _, err := agent.GetLocalUserCredentials()
				require.NoError(t, err)
				before := responsesForAgent(host.trace, ufrag)
				require.Eventually(t, func() bool {
					return responsesForAgent(host.trace, ufrag) >= before+3
				}, 3*time.Second, 10*time.Millisecond, "replacement must receive fresh check responses after old agent removal")
				assertReplacementRouting(t, host.trace, ufrag, oldUfrags[side])
			}
		})
	}
}

func assertReplacementRouting(t *testing.T, trace *stunTrace, liveUfrag, removedUfrag string) {
	t.Helper()
	trace.mu.Lock()
	defer trace.mu.Unlock()
	livePrefix := liveUfrag + "/"
	for id, readers := range trace.requestReaders {
		responders := trace.responseWriters[id]
		switch trace.requestUfrags[id] {
		case liveUfrag:
			assert.Len(t, readers, 1, "live request %x must have one recipient", id[:4])
			for _, reader := range readers {
				assert.True(t, strings.HasPrefix(reader, livePrefix), "live request %x reached %s", id[:4], reader)
			}
			assert.LessOrEqual(t, len(responders), 1, "live request %x must be answered at most once", id[:4])
			if len(readers) == 1 {
				for _, responder := range responders {
					assert.Equal(t, readers[0], responder, "live request %x must be answered by its recipient", id[:4])
				}
			}
		case removedUfrag:
			// The other old agent may still transmit while Close removes this
			// ufrag. Its now-unknown requests intentionally use address fallback;
			// surviving agents must reject them without answering.
			for _, responder := range responders {
				assert.False(t, strings.HasPrefix(responder, livePrefix), "replacement answered removed-agent request %x", id[:4])
			}
		}
	}
	for id, readers := range trace.responseReaders {
		for _, writer := range trace.requestWriters[id] {
			if strings.HasPrefix(writer, livePrefix) {
				assert.Equal(t, []string{writer}, readers, "live response %x must reach only its requesting conn", id[:4])
			}
		}
	}
}

func newKeepaliveAgent(t *testing.T, host *muxHost) *ice.Agent {
	t.Helper()
	interval := 50 * time.Millisecond
	agent, err := ice.NewAgent(&ice.AgentConfig{
		NetworkTypes:      []ice.NetworkType{ice.NetworkTypeUDP4},
		CandidateTypes:    []ice.CandidateType{ice.CandidateTypeHost, ice.CandidateTypeServerReflexive},
		Urls:              []*stun.URI{host.lab.stunURL},
		UDPMux:            &observedHostMux{UDPMux: host.mux.SingleSocketUDPMux, trace: host.trace},
		UDPMuxSrflx:       &observedSrflxMux{UniversalUDPMux: host.mux, trace: host.trace},
		Net:               host.net,
		MulticastDNSMode:  ice.MulticastDNSModeDisabled,
		LoggerFactory:     quietLoggerFactory(),
		KeepaliveInterval: &interval,
	})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, agent.Close()) })
	return agent
}

func responsesForAgent(trace *stunTrace, ufrag string) int {
	trace.mu.Lock()
	defer trace.mu.Unlock()
	var count int
	for id, readers := range trace.responseReaders {
		writers := trace.requestWriters[id]
		if len(writers) == 0 || !strings.HasPrefix(writers[len(writers)-1], ufrag+"/") {
			continue
		}
		for _, reader := range readers {
			if reader == writers[len(writers)-1] {
				count++
				break
			}
		}
	}
	return count
}

type heldOrderingMessage struct {
	message *stun.Message
	address net.Addr
}

type nominationOrderingConn struct {
	net.PacketConn
	mux        *UniversalUDPMuxDefault
	mu         sync.Mutex
	released   bool
	nomination transactionID
	held       []heldOrderingMessage
	pending    *heldOrderingMessage
	heldCount  int
}

func (c *nominationOrderingConn) handleIncoming(msg *stun.Message, addr net.Addr) error {
	if addr.String() == fmt.Sprintf("%s:%d", vnetSTUNServerIP, vnetSTUNServerPort) {
		return c.mux.HandleSTUNMessage(msg, addr)
	}
	c.mu.Lock()
	if c.released {
		c.mu.Unlock()
		return c.mux.HandleSTUNMessage(msg, addr)
	}
	if msg.Type == stun.BindingRequest && msg.Contains(stun.AttrUseCandidate) {
		c.nomination = msg.TransactionID
		if len(c.held) == 0 {
			c.pending = &heldOrderingMessage{message: msg, address: addr}
			c.mu.Unlock()
			return nil
		}
	}
	if msg.Type != stun.BindingSuccess {
		c.mu.Unlock()
		return c.mux.HandleSTUNMessage(msg, addr)
	}
	c.held = append(c.held, heldOrderingMessage{message: msg, address: addr})
	c.heldCount++
	pending := c.pending
	c.pending = nil
	c.mu.Unlock()
	if pending != nil {
		return c.mux.HandleSTUNMessage(pending.message, pending.address)
	}
	return nil
}

func (c *nominationOrderingConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	n, err := c.PacketConn.WriteTo(b, addr)
	if err != nil {
		return n, err
	}
	msg := &stun.Message{Raw: b}
	if err := msg.Decode(); err != nil {
		return n, fmt.Errorf("decode outgoing check: %w", err)
	}
	c.mu.Lock()
	if c.released || msg.Type != stun.BindingSuccess || msg.TransactionID != c.nomination {
		c.mu.Unlock()
		return n, nil
	}
	c.released = true
	held := c.held
	c.held = nil
	c.mu.Unlock()
	for _, response := range held {
		if err := c.mux.HandleSTUNMessage(response.message, response.address); err != nil {
			return n, err
		}
	}
	return n, nil
}

func newNominationOrderingHost(t *testing.T, lab *natLab, host natedHost, strip bool) (*muxHost, *nominationOrderingConn) {
	t.Helper()
	conn, err := host.net.ListenPacket("udp4", host.ip+":51820")
	require.NoError(t, err)
	if strip {
		conn = &pairIDStrippingConn{PacketConn: conn}
	}
	gate := &nominationOrderingConn{PacketConn: conn}
	gate.mux = NewUniversalUDPMuxDefault(UniversalUDPMuxParams{UDPConn: gate, Net: host.net, MTU: 1280})
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, receiveMTU)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			msg := &stun.Message{Raw: append([]byte(nil), buf[:n]...)}
			if !assert.NoError(t, msg.Decode()) {
				return
			}
			assert.NoError(t, gate.handleIncoming(msg, addr))
		}
	}()
	t.Cleanup(func() {
		assert.NoError(t, gate.mux.Close())
		<-done
	})
	return &muxHost{lab: lab, net: host.net, mux: gate.mux, trace: newSTUNTrace()}, gate
}
