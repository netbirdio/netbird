package udpmux

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/stun/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRouting_MultipleHostCandidates(t *testing.T) {
	for _, controlling := range []bool{false, true} {
		t.Run(fmt.Sprintf("controlling=%t", controlling), func(t *testing.T) {
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
				UDPMux:           hostMux,
				UDPMuxSrflx:      &candidateSrflxMux{UniversalUDPMux: mux, trace: trace},
				Net:              host.net,
				MulticastDNSMode: ice.MulticastDNSModeDisabled,
				LoggerFactory:    quietLoggerFactory(),
			})
			require.NoError(t, err)
			t.Cleanup(func() { assert.NoError(t, agent.Close()) })
			peerHost := newMuxHost(t, lab, lab.addNATedHost(t), true)
			peer := peerHost.newAgent(t)
			lab.start(t)

			localCandidates, peerCandidates := gather(t, agent), gather(t, peer)
			candidates, err := agent.GetLocalCandidates()
			require.NoError(t, err)
			hostAddresses := make(map[string]bool)
			var srflx int
			for _, candidate := range candidates {
				switch candidate.Type() {
				case ice.CandidateTypeHost:
					hostAddresses[candidate.Address()] = true
				case ice.CandidateTypeServerReflexive:
					srflx++
				}
			}
			require.Equal(t, map[string]bool{host.ip: true, "127.0.0.1": true}, hostAddresses)
			require.Equal(t, 1, srflx, "the second candidate type must come from an actual STUN exchange")
			hostMux.activate()
			connectCandidateAgents(t, agent, peer, localCandidates, peerCandidates, controlling)

			assertRouting(t, "candidate identities", &muxHost{trace: trace})
			assertRouting(t, "peer without pair ID", peerHost)
			trace.mu.Lock()
			recipients := make(map[string]bool)
			for _, readers := range trace.requestReaders {
				for _, reader := range readers {
					recipients[reader] = true
				}
			}
			trace.mu.Unlock()
			assert.Len(t, recipients, 1, "USERNAME-only requests must consistently reach one host candidate")

			require.NoError(t, agent.Close())
			for conn := range hostMux.groups {
				muxed, ok := conn.(*udpMuxedConn)
				require.True(t, ok)
				assert.True(t, muxed.isClosed(), "closing the agent must close every host candidate queue")
			}
			mux.mu.Lock()
			assert.Empty(t, mux.candidateConnMap, "closing the agent must remove every candidate route")
			mux.mu.Unlock()
		})
	}
}

func connectCandidateAgents(t *testing.T, agent, peer *ice.Agent, localCandidates, peerCandidates []string, controlling bool) {
	t.Helper()
	for side, candidates := range [][]string{peerCandidates, localCandidates} {
		for _, raw := range candidates {
			candidate, err := ice.UnmarshalCandidate(raw)
			require.NoError(t, err)
			require.NoError(t, []*ice.Agent{agent, peer}[side].AddRemoteCandidate(candidate))
		}
	}
	localUfrag, localPwd, err := agent.GetLocalUserCredentials()
	require.NoError(t, err)
	peerUfrag, peerPwd, err := peer.GetLocalUserCredentials()
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	results := make(chan error, 2)
	go func() {
		var err error
		if controlling {
			_, err = agent.Dial(ctx, peerUfrag, peerPwd)
		} else {
			_, err = agent.Accept(ctx, peerUfrag, peerPwd)
		}
		results <- err
	}()
	go func() {
		var err error
		if controlling {
			_, err = peer.Accept(ctx, localUfrag, localPwd)
		} else {
			_, err = peer.Dial(ctx, localUfrag, localPwd)
		}
		results <- err
	}()
	first, second := <-results, <-results
	assert.NoError(t, first, "both agents must connect despite competing candidate readers")
	assert.NoError(t, second, "both agents must connect despite competing candidate readers")
}

type candidateHostMux struct {
	ice.UDPMux
	trace  *stunTrace
	mu     sync.Mutex
	groups map[net.PacketConn]*candidateReadGroup
}

func (m *candidateHostMux) GetConn(ufrag string, addr net.Addr, candidateID string) (net.PacketConn, error) {
	conn, err := m.UDPMux.GetConn(ufrag, addr, candidateID)
	if err != nil {
		return nil, err
	}
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return nil, fmt.Errorf("expected UDP address, got %T", addr)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	group := m.groups[conn]
	if group == nil {
		group = &candidateReadGroup{conn: conn, ready: make(chan struct{}), queues: make(map[bool]chan candidateReadPacket)}
		m.groups[conn] = group
	}
	queue := make(chan candidateReadPacket, 128)
	group.queues[udpAddr.IP.IsLoopback()] = queue
	return &candidateReadConn{
		observedConn: &observedConn{PacketConn: conn, name: ufrag + "/host/" + candidateID, trace: m.trace},
		group:        group,
		queue:        queue,
	}, nil
}

func (m *candidateHostMux) activate() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, group := range m.groups {
		if len(group.queues) > 1 {
			go group.schedule()
		}
		close(group.ready)
	}
}

type candidateSrflxMux struct {
	ice.UniversalUDPMux
	trace *stunTrace
}

func (m *candidateSrflxMux) GetConnForURL(ufrag, url string, addr net.Addr, candidateID string) (net.PacketConn, error) {
	conn, err := m.UniversalUDPMux.GetConnForURL(ufrag, url, addr, candidateID)
	if err != nil {
		return nil, err
	}
	return &observedConn{PacketConn: conn, name: ufrag + "/srflx/" + candidateID, trace: m.trace}, nil
}

type candidateReadPacket struct {
	data []byte
	addr net.Addr
}

type candidateReadGroup struct {
	conn   net.PacketConn
	ready  chan struct{}
	queues map[bool]chan candidateReadPacket
}

type candidateReadConn struct {
	*observedConn
	group *candidateReadGroup
	queue <-chan candidateReadPacket
}

func (c *candidateReadConn) ReadFrom(b []byte) (int, net.Addr, error) {
	<-c.group.ready
	if len(c.group.queues) == 1 {
		return c.observedConn.ReadFrom(b)
	}
	packet, ok := <-c.queue
	if !ok {
		return 0, nil, io.EOF
	}
	n := copy(b, packet.data)
	c.trace.observe(c.name, b[:n], false)
	return n, packet.addr, nil
}

// When multiple candidates share a conn, reproduce a permitted reader order:
// loopback consumes nomination, while the physical candidate consumes responses.
// Every mux-delivered packet reaches one reader. Distinct candidate conns bypass
// this scheduler, preserving their own read queues.
func (g *candidateReadGroup) schedule() {
	defer func() {
		for _, queue := range g.queues {
			close(queue)
		}
	}()
	for {
		b := make([]byte, receiveMTU)
		n, addr, err := g.conn.ReadFrom(b)
		if err != nil {
			return
		}
		msg := &stun.Message{Raw: b[:n]}
		nomination := msg.Decode() == nil && msg.Type == stun.BindingRequest && msg.Contains(stun.AttrUseCandidate)
		g.queues[nomination] <- candidateReadPacket{data: b[:n], addr: addr}
	}
}
