package udpmux

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/logging"
	"github.com/pion/stun/v3"
	"github.com/pion/transport/v3/vnet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAgentRoutingHostAndServerReflexive(t *testing.T) {
	testAgentRouting(t, 1, true)
}

func TestAgentRoutingOverlappingAgents(t *testing.T) {
	testAgentRouting(t, 2, true)
}

func TestAgentRoutingManyAgents(t *testing.T) {
	testAgentRouting(t, 20, true)
}

func TestAgentRoutingMixedPairID(t *testing.T) {
	for _, strip := range []bool{false, true} {
		t.Run(fmt.Sprintf("peer_without_pair_id=%t", strip), func(t *testing.T) {
			testAgentRouting(t, 1, strip)
		})
	}
}

type agentRoutingTrace struct {
	mu                 sync.Mutex
	owners             map[[stun.TransactionIDSize]byte]string
	writers            map[string]int
	requests           map[[stun.TransactionIDSize]byte]int
	responses          map[[stun.TransactionIDSize]byte]int
	inboundResponses   map[[stun.TransactionIDSize]byte]int
	deliveredResponses map[[stun.TransactionIDSize]byte]int
	responseReads      int
	pairIDWrites       int
	withoutIDWrites    int
	misrouted          []string
	errors             []error
}

func newAgentRoutingTrace() *agentRoutingTrace {
	return &agentRoutingTrace{
		owners:             make(map[[stun.TransactionIDSize]byte]string),
		writers:            make(map[string]int),
		requests:           make(map[[stun.TransactionIDSize]byte]int),
		responses:          make(map[[stun.TransactionIDSize]byte]int),
		inboundResponses:   make(map[[stun.TransactionIDSize]byte]int),
		deliveredResponses: make(map[[stun.TransactionIDSize]byte]int),
	}
}

// These wrappers observe real mux connections; all transport and routing use the
// production mux, the fork's agents, and a virtual network with two NATs.
type agentRoutingMux struct {
	*UniversalUDPMuxDefault
	trace *agentRoutingTrace
	strip bool
}

func (m *agentRoutingMux) GetConn(ufrag string, addr net.Addr, candidateID string) (net.PacketConn, error) {
	conn, err := m.UniversalUDPMuxDefault.GetConn(ufrag, addr, candidateID)
	if err != nil {
		return nil, err
	}
	return &agentRoutingConn{PacketConn: conn, mux: m, key: ufrag, kind: "host"}, nil
}

func (m *agentRoutingMux) GetConnForURL(ufrag, url string, addr net.Addr, candidateID string) (net.PacketConn, error) {
	conn, err := m.UniversalUDPMuxDefault.GetConnForURL(ufrag, url, addr, candidateID)
	if err != nil {
		return nil, err
	}
	return &agentRoutingConn{PacketConn: conn, mux: m, key: ufrag + url, kind: "srflx"}, nil
}

type agentRoutingConn struct {
	net.PacketConn
	mux  *agentRoutingMux
	key  string
	kind string
}

func (c *agentRoutingConn) WriteTo(buf []byte, addr net.Addr) (int, error) {
	msg := &stun.Message{Raw: append([]byte(nil), buf...)}
	if msg.Decode() != nil {
		return c.PacketConn.WriteTo(buf, addr)
	}
	if c.mux.strip {
		// The fork appends this attribute after integrity and fingerprint. Removing
		// the trailing attribute restores the original authenticated message.
		if pairID, err := msg.Get(ice.AttrCandidatePairID); err == nil {
			length := 4 + (len(pairID)+3)&^3
			msg.Raw = msg.Raw[:len(msg.Raw)-length]
			binary.BigEndian.PutUint16(msg.Raw[2:4], uint16(len(msg.Raw)-20))
			if err := msg.Decode(); err != nil {
				return 0, err
			}
		}
	}
	trace := c.mux.trace
	trace.mu.Lock()
	if _, err := msg.Get(ice.AttrCandidatePairID); err == nil {
		trace.pairIDWrites++
	} else {
		trace.withoutIDWrites++
	}
	switch msg.Type.Class {
	case stun.ClassRequest:
		trace.owners[msg.TransactionID] = c.key
		trace.writers[c.kind]++
	case stun.ClassSuccessResponse, stun.ClassErrorResponse:
		trace.responses[msg.TransactionID]++
	}
	trace.mu.Unlock()
	n, err := c.PacketConn.WriteTo(msg.Raw, addr)
	if err != nil {
		return n, err
	}
	return len(buf), nil
}

func (c *agentRoutingConn) ReadFrom(buf []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(buf)
	if err != nil {
		return n, addr, err
	}
	msg := &stun.Message{Raw: buf[:n]}
	if msg.Decode() != nil || (msg.Type.Class != stun.ClassSuccessResponse && msg.Type.Class != stun.ClassErrorResponse) {
		return n, addr, nil
	}
	trace := c.mux.trace
	trace.mu.Lock()
	trace.responseReads++
	trace.deliveredResponses[msg.TransactionID]++
	if owner := trace.owners[msg.TransactionID]; owner != c.key {
		trace.misrouted = append(trace.misrouted, fmt.Sprintf("%x: sent by %s, read by %s", msg.TransactionID, owner, c.key))
	}
	trace.mu.Unlock()
	return n, addr, nil
}

func testAgentRouting(t *testing.T, count int, stripPeerPairID bool) {
	t.Helper()
	nets := newAgentRoutingNetwork(t)
	muxes := [2]*agentRoutingMux{
		newAgentRoutingMux(t, nets[0], "10.0.0.2:51820", false),
		newAgentRoutingMux(t, nets[1], "10.0.1.2:51820", stripPeerPairID),
	}
	pairs := make([][2]*ice.Agent, count)
	for i := range pairs {
		for side := range muxes {
			pairs[i][side] = newRoutingAgent(t, nets[side], muxes[side])
		}
		exchangeRoutingCandidates(t, pairs[i])
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	results := make(chan error, 2*count)
	started := time.Now()
	for _, pair := range pairs {
		for side, agent := range pair {
			ufrag, pwd, err := pair[1-side].GetLocalUserCredentials()
			require.NoError(t, err)
			go func() {
				var err error
				if side == 0 {
					_, err = agent.Dial(ctx, ufrag, pwd)
				} else {
					_, err = agent.Accept(ctx, ufrag, pwd)
				}
				results <- err
			}()
		}
	}
	for range 2 * count {
		require.NoError(t, <-results, "each real agent must connect through the shared socket")
	}
	t.Logf("%d agent pairs connected in %s", count, time.Since(started))
	for i, pair := range pairs {
		for side, agent := range pair {
			selected, err := agent.GetSelectedCandidatePair()
			require.NoError(t, err)
			require.NotNil(t, selected, "pair %d side %d must select a candidate pair", i, side)
			t.Logf("pair %d side %d local=%s remote=%s", i, side, selected.Local.Type(), selected.Remote.Type())
		}
	}
	for side, mux := range muxes {
		assertRoutingTrace(t, mux, count, side == 1 && stripPeerPairID)
	}
}

func assertRoutingTrace(t *testing.T, mux *agentRoutingMux, agents int, stripped bool) {
	t.Helper()
	trace := mux.trace
	require.Eventually(t, func() bool {
		trace.mu.Lock()
		defer trace.mu.Unlock()
		for id, requests := range trace.requests {
			if trace.responses[id] < requests {
				return false
			}
		}
		for id, responses := range trace.inboundResponses {
			if trace.deliveredResponses[id] < responses {
				return false
			}
		}
		return trace.responseReads > 0
	}, time.Second, time.Millisecond, "agents must respond to every received check")
	trace.mu.Lock()
	defer trace.mu.Unlock()
	assert.Empty(t, trace.errors, "the real socket reader must handle every STUN message")
	assert.Empty(t, trace.misrouted, "responses must reach only the connection that sent the request")
	assert.GreaterOrEqual(t, trace.writers["host"], agents, "every agent must send checks from its host connection")
	assert.GreaterOrEqual(t, trace.writers["srflx"], agents, "every agent must send checks from its srflx connection")
	assert.NotEmpty(t, trace.requests, "remote checks must arrive over the NAT")
	for id, requests := range trace.requests {
		assert.Equal(t, requests, trace.responses[id], "transaction %x must have exactly one response per received request", id)
	}
	assert.Equal(t, trace.inboundResponses, trace.deliveredResponses, "each response must be delivered to exactly one connection")
	if stripped {
		assert.Zero(t, trace.pairIDWrites, "legacy peer must not put pair IDs on the wire")
		assert.Positive(t, trace.withoutIDWrites, "legacy peer must send STUN")
		return
	}
	assert.Positive(t, trace.pairIDWrites, "current peer must put pair IDs on the wire")
}

func newAgentRoutingNetwork(t *testing.T) [2]*vnet.Net {
	t.Helper()
	logger := logging.NewDefaultLoggerFactory()
	logger.DefaultLogLevel = logging.LogLevelError
	wan, err := vnet.NewRouter(&vnet.RouterConfig{CIDR: "0.0.0.0/0", LoggerFactory: logger})
	require.NoError(t, err)
	serverNet, err := vnet.NewNet(&vnet.NetConfig{StaticIPs: []string{"192.0.2.1"}})
	require.NoError(t, err)
	require.NoError(t, wan.AddNet(serverNet))
	var nets [2]*vnet.Net
	for side := range nets {
		lan, err := vnet.NewRouter(&vnet.RouterConfig{
			CIDR:          fmt.Sprintf("10.0.%d.0/24", side),
			StaticIPs:     []string{fmt.Sprintf("192.0.2.%d", side+2)},
			NATType:       &vnet.NATType{MappingBehavior: vnet.EndpointIndependent, FilteringBehavior: vnet.EndpointIndependent},
			LoggerFactory: logger,
		})
		require.NoError(t, err)
		nets[side], err = vnet.NewNet(&vnet.NetConfig{StaticIPs: []string{fmt.Sprintf("10.0.%d.2", side)}})
		require.NoError(t, err)
		require.NoError(t, lan.AddNet(nets[side]))
		require.NoError(t, wan.AddRouter(lan))
	}
	require.NoError(t, wan.Start())
	t.Cleanup(func() { assert.NoError(t, wan.Stop()) })
	server, err := serverNet.ListenPacket("udp4", "192.0.2.1:3478")
	require.NoError(t, err)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		for {
			n, addr, err := server.ReadFrom(buf)
			if err != nil {
				return
			}
			msg := &stun.Message{Raw: buf[:n]}
			if msg.Decode() != nil {
				continue
			}
			udpAddr, ok := addr.(*net.UDPAddr)
			if !ok {
				t.Error("virtual STUN server received a non-UDP address")
				return
			}
			response, err := stun.Build(stun.BindingSuccess, stun.NewTransactionIDSetter(msg.TransactionID),
				&stun.XORMappedAddress{IP: udpAddr.IP, Port: udpAddr.Port})
			if !assert.NoError(t, err) {
				return
			}
			if _, err := server.WriteTo(response.Raw, addr); !assert.NoError(t, err) {
				return
			}
		}
	}()
	t.Cleanup(func() {
		assert.NoError(t, server.Close())
		<-done
	})
	return nets
}

func newAgentRoutingMux(t *testing.T, network *vnet.Net, address string, strip bool) *agentRoutingMux {
	t.Helper()
	conn, err := network.ListenPacket("udp4", address)
	require.NoError(t, err)
	mux := &agentRoutingMux{
		UniversalUDPMuxDefault: NewUniversalUDPMuxDefault(UniversalUDPMuxParams{UDPConn: conn, Net: network, MTU: 1500}),
		trace:                  newAgentRoutingTrace(), strip: strip,
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			msg := &stun.Message{Raw: buf[:n]}
			if msg.Decode() != nil {
				continue
			}
			mux.trace.mu.Lock()
			switch msg.Type.Class {
			case stun.ClassRequest:
				mux.trace.requests[msg.TransactionID]++
			case stun.ClassSuccessResponse, stun.ClassErrorResponse:
				if _, ok := mux.trace.owners[msg.TransactionID]; ok {
					mux.trace.inboundResponses[msg.TransactionID]++
				}
			}
			mux.trace.mu.Unlock()
			if err := mux.HandleSTUNMessage(msg, addr); err != nil {
				mux.trace.mu.Lock()
				mux.trace.errors = append(mux.trace.errors, err)
				mux.trace.mu.Unlock()
			}
		}
	}()
	t.Cleanup(func() {
		assert.NoError(t, mux.Close())
		<-done
	})
	return mux
}

func newRoutingAgent(t *testing.T, network *vnet.Net, mux *agentRoutingMux) *ice.Agent {
	t.Helper()
	zero := time.Duration(0)
	interval := 20 * time.Millisecond
	logger := logging.NewDefaultLoggerFactory()
	logger.DefaultLogLevel = logging.LogLevelError
	agent, err := ice.NewAgent(&ice.AgentConfig{
		Net: network, UDPMux: mux, UDPMuxSrflx: mux,
		Urls:                   []*stun.URI{{Scheme: stun.SchemeTypeSTUN, Host: "192.0.2.1", Port: 3478, Proto: stun.ProtoTypeUDP}},
		CandidateTypes:         []ice.CandidateType{ice.CandidateTypeHost, ice.CandidateTypeServerReflexive},
		NetworkTypes:           []ice.NetworkType{ice.NetworkTypeUDP4},
		MulticastDNSMode:       ice.MulticastDNSModeDisabled,
		KeepaliveInterval:      &zero,
		CheckInterval:          &interval,
		SrflxAcceptanceMinWait: &zero,
		LoggerFactory:          logger,
	})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, agent.Close()) })
	complete := make(chan struct{})
	require.NoError(t, agent.OnCandidate(func(candidate ice.Candidate) {
		if candidate == nil {
			close(complete)
		}
	}))
	require.NoError(t, agent.GatherCandidates())
	select {
	case <-complete:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out gathering candidates through the virtual NAT")
	}
	candidates, err := agent.GetLocalCandidates()
	require.NoError(t, err)
	var types []ice.CandidateType
	for _, candidate := range candidates {
		types = append(types, candidate.Type())
	}
	require.ElementsMatch(t, []ice.CandidateType{ice.CandidateTypeHost, ice.CandidateTypeServerReflexive}, types,
		"every agent must gather host and actual STUN-derived srflx candidates")
	return agent
}

func exchangeRoutingCandidates(t *testing.T, pair [2]*ice.Agent) {
	t.Helper()
	for side, agent := range pair {
		candidates, err := agent.GetLocalCandidates()
		require.NoError(t, err)
		for _, candidate := range candidates {
			remote, err := ice.UnmarshalCandidate(candidate.Marshal())
			require.NoError(t, err)
			require.NoError(t, pair[1-side].AddRemoteCandidate(remote))
		}
	}
}
