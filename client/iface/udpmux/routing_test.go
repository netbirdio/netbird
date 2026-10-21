package udpmux

import (
	"context"
	"fmt"
	"net"
	"sort"
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

// These tests run real ICE agents on real muxes connected through a virtual
// network with NAT routers, so every agent gathers a host and a server
// reflexive candidate on one shared socket, as the NetBird agent does behind NAT.
// A passive observer between each agent and its mux records which muxed conn
// writes and reads every STUN message.

const (
	vnetSTUNServerIP   = "1.2.3.4"
	vnetSTUNServerPort = 3478
	connectTimeout     = 30 * time.Second
)

type txID = [stun.TransactionIDSize]byte

// stunTrace records, per transaction ID, which muxed conns wrote and read STUN
// requests and responses on one mux.
type stunTrace struct {
	mu              sync.Mutex
	requestWriters  map[txID][]string
	requestReaders  map[txID][]string
	responseWriters map[txID][]string
	responseReaders map[txID][]string
}

func newSTUNTrace() *stunTrace {
	return &stunTrace{
		requestWriters:  make(map[txID][]string),
		requestReaders:  make(map[txID][]string),
		responseWriters: make(map[txID][]string),
		responseReaders: make(map[txID][]string),
	}
}

func (s *stunTrace) observe(conn string, b []byte, written bool) {
	msg := &stun.Message{Raw: append([]byte(nil), b...)}
	if err := msg.Decode(); err != nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	isResponse := msg.Type.Class == stun.ClassSuccessResponse || msg.Type.Class == stun.ClassErrorResponse
	switch {
	case msg.Type.Class == stun.ClassRequest && written:
		s.requestWriters[msg.TransactionID] = append(s.requestWriters[msg.TransactionID], conn)
	case msg.Type.Class == stun.ClassRequest:
		s.requestReaders[msg.TransactionID] = append(s.requestReaders[msg.TransactionID], conn)
	case isResponse && written:
		s.responseWriters[msg.TransactionID] = append(s.responseWriters[msg.TransactionID], conn)
	case isResponse:
		s.responseReaders[msg.TransactionID] = append(s.responseReaders[msg.TransactionID], conn)
	}
}

// responseMisdeliveries lists every response that was read by anything other
// than exactly the one conn that wrote its request.
func (s *stunTrace) responseMisdeliveries() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []string
	for id, readers := range s.responseReaders {
		writers := s.requestWriters[id]
		if len(writers) == 0 || len(readers) != 1 || readers[0] != writers[len(writers)-1] {
			out = append(out, fmt.Sprintf("tx %x: request written by %v, response read by %v", id[:4], writers, readers))
		}
	}
	sort.Strings(out)
	return out
}

// requestDuplicates lists every request read by more than one conn or
// answered more than once.
func (s *stunTrace) requestDuplicates() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []string
	for id, readers := range s.requestReaders {
		responders := s.responseWriters[id]
		if len(readers) != 1 || len(responders) > 1 {
			out = append(out, fmt.Sprintf("tx %x: request read by %v, answered by %v", id[:4], readers, responders))
		}
	}
	sort.Strings(out)
	return out
}

func (s *stunTrace) counts() (requestsRead, responsesRead int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.requestReaders), len(s.responseReaders)
}

// observedConn passes everything through to the muxed conn and records the
// STUN messages the agent writes to and reads from it.
type observedConn struct {
	net.PacketConn
	name  string
	trace *stunTrace
}

func (c *observedConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if err == nil {
		c.trace.observe(c.name, b[:n], false)
	}
	return n, addr, err
}

func (c *observedConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.trace.observe(c.name, b, true)
	return c.PacketConn.WriteTo(b, addr)
}

// observedHostMux hands the agent the real mux, wrapping only the conns it returns.
type observedHostMux struct {
	ice.UDPMux
	trace *stunTrace
}

func (m *observedHostMux) GetConn(ufrag string, addr net.Addr, candidateID string) (net.PacketConn, error) {
	conn, err := m.UDPMux.GetConn(ufrag, addr, candidateID)
	if err != nil {
		return nil, err
	}
	return &observedConn{PacketConn: conn, name: ufrag + "/host", trace: m.trace}, nil
}

type observedSrflxMux struct {
	ice.UniversalUDPMux
	trace *stunTrace
}

func (m *observedSrflxMux) GetConnForURL(ufrag string, url string, addr net.Addr, candidateID string) (net.PacketConn, error) {
	conn, err := m.UniversalUDPMux.GetConnForURL(ufrag, url, addr, candidateID)
	if err != nil {
		return nil, err
	}
	return &observedConn{PacketConn: conn, name: ufrag + "/srflx", trace: m.trace}, nil
}

// pairIDStrippingConn removes the candidate pair ID attribute from every STUN
// message leaving the socket, so the remote mux sees what an ICE agent without
// the attribute would send. The attribute is appended last, after FINGERPRINT,
// so removing it restores the message the agent built.
type pairIDStrippingConn struct {
	net.PacketConn
}

func (c *pairIDStrippingConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if _, err := c.PacketConn.WriteTo(stripPairID(b), addr); err != nil {
		return 0, err
	}
	return len(b), nil
}

func stripPairID(b []byte) []byte {
	msg := &stun.Message{Raw: append([]byte(nil), b...)}
	if err := msg.Decode(); err != nil || !msg.Contains(ice.AttrCandidatePairID) {
		return b
	}

	out := &stun.Message{Type: msg.Type, TransactionID: msg.TransactionID}
	out.WriteHeader()
	for _, attr := range msg.Attributes {
		if attr.Type != ice.AttrCandidatePairID {
			out.Add(attr.Type, attr.Value)
		}
	}
	return out.Raw
}

// natLab is a virtual internet with a STUN server, to which NATed hosts attach.
type natLab struct {
	wan     *vnet.Router
	stunURL *stun.URI
	hosts   int
}

func newNATLab(t *testing.T) *natLab {
	t.Helper()

	wan, err := vnet.NewRouter(&vnet.RouterConfig{CIDR: "0.0.0.0/0", LoggerFactory: quietLoggerFactory()})
	require.NoError(t, err)

	stunNet, err := vnet.NewNet(&vnet.NetConfig{StaticIP: vnetSTUNServerIP})
	require.NoError(t, err)
	require.NoError(t, wan.AddNet(stunNet))

	stunConn, err := stunNet.ListenPacket("udp4", fmt.Sprintf("%s:%d", vnetSTUNServerIP, vnetSTUNServerPort))
	require.NoError(t, err)
	go serveSTUN(stunConn)

	stunURL, err := stun.ParseURI(fmt.Sprintf("stun:%s:%d", vnetSTUNServerIP, vnetSTUNServerPort))
	require.NoError(t, err)

	lab := &natLab{wan: wan, stunURL: stunURL}
	t.Cleanup(func() {
		_ = stunConn.Close()
		_ = wan.Stop()
	})
	return lab
}

// serveSTUN answers binding requests with the source address seen by the server.
func serveSTUN(conn net.PacketConn) {
	buf := make([]byte, receiveMTU)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		req := &stun.Message{Raw: append([]byte(nil), buf[:n]...)}
		if err := req.Decode(); err != nil || req.Type != stun.BindingRequest {
			continue
		}
		udpAddr, ok := addr.(*net.UDPAddr)
		if !ok {
			continue
		}
		resp, err := stun.Build(req, stun.BindingSuccess,
			&stun.XORMappedAddress{IP: udpAddr.IP, Port: udpAddr.Port}, stun.Fingerprint)
		if err != nil {
			continue
		}
		_, _ = conn.WriteTo(resp.Raw, addr)
	}
}

type natedHost struct {
	net *vnet.Net
	ip  string
}

// addNATedHost attaches a host behind its own endpoint-independent-mapping,
// port-restricted NAT, the common home router behaviour.
func (l *natLab) addNATedHost(t *testing.T) natedHost {
	t.Helper()
	l.hosts++
	ip := fmt.Sprintf("10.%d.0.2", l.hosts)

	router, err := vnet.NewRouter(&vnet.RouterConfig{
		StaticIPs: []string{fmt.Sprintf("27.1.%d.1", l.hosts)},
		CIDR:      fmt.Sprintf("10.%d.0.0/24", l.hosts),
		NATType: &vnet.NATType{
			MappingBehavior:   vnet.EndpointIndependent,
			FilteringBehavior: vnet.EndpointAddrPortDependent,
		},
		LoggerFactory: quietLoggerFactory(),
	})
	require.NoError(t, err)

	hostNet, err := vnet.NewNet(&vnet.NetConfig{StaticIPs: []string{ip}})
	require.NoError(t, err)
	require.NoError(t, router.AddNet(hostNet))
	require.NoError(t, l.wan.AddRouter(router))
	return natedHost{net: hostNet, ip: ip}
}

func (l *natLab) start(t *testing.T) {
	t.Helper()
	require.NoError(t, l.wan.Start())
}

// muxHost is one NetBird-like host: a single socket shared through the
// universal mux by every ICE agent on the host.
type muxHost struct {
	lab   *natLab
	net   *vnet.Net
	mux   *UniversalUDPMuxDefault
	trace *stunTrace
}

func newMuxHost(t *testing.T, lab *natLab, host natedHost, stripPairIDs bool) *muxHost {
	t.Helper()

	conn, err := host.net.ListenPacket("udp4", host.ip+":51820")
	require.NoError(t, err)
	if stripPairIDs {
		conn = &pairIDStrippingConn{PacketConn: conn}
	}

	mux := NewUniversalUDPMuxDefault(UniversalUDPMuxParams{UDPConn: conn, Net: host.net, MTU: 1280})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		mux.ReadFromConn(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		_ = mux.Close()
		<-done
	})

	return &muxHost{lab: lab, net: host.net, mux: mux, trace: newSTUNTrace()}
}

func (h *muxHost) newAgent(t *testing.T) *ice.Agent {
	t.Helper()

	agent, err := ice.NewAgent(&ice.AgentConfig{
		NetworkTypes:     []ice.NetworkType{ice.NetworkTypeUDP4},
		CandidateTypes:   []ice.CandidateType{ice.CandidateTypeHost, ice.CandidateTypeServerReflexive},
		Urls:             []*stun.URI{h.lab.stunURL},
		UDPMux:           &observedHostMux{UDPMux: h.mux.SingleSocketUDPMux, trace: h.trace},
		UDPMuxSrflx:      &observedSrflxMux{UniversalUDPMux: h.mux, trace: h.trace},
		Net:              h.net,
		MulticastDNSMode: ice.MulticastDNSModeDisabled,
		LoggerFactory:    quietLoggerFactory(),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = agent.Close() })
	return agent
}

// gather collects the agent's candidates, serialised as they would be signalled.
func gather(t *testing.T, agent *ice.Agent) []string {
	t.Helper()

	var mu sync.Mutex
	var candidates []string
	done := make(chan struct{})
	require.NoError(t, agent.OnCandidate(func(c ice.Candidate) {
		if c == nil {
			close(done)
			return
		}
		mu.Lock()
		candidates = append(candidates, c.Marshal())
		mu.Unlock()
	}))
	require.NoError(t, agent.GatherCandidates())

	select {
	case <-done:
	case <-time.After(connectTimeout):
		t.Fatal("candidate gathering did not complete")
	}

	mu.Lock()
	defer mu.Unlock()
	return candidates
}

type agentPair struct {
	controlling, controlled *ice.Agent
}

// connect exchanges credentials and the complete candidate lists, then runs the
// connectivity checks of every pair concurrently.
func connect(t *testing.T, pairs []agentPair) {
	t.Helper()

	type signalled struct {
		ufrag, pwd string
		candidates []string
	}
	describe := func(agent *ice.Agent) signalled {
		ufrag, pwd, err := agent.GetLocalUserCredentials()
		require.NoError(t, err)
		return signalled{ufrag: ufrag, pwd: pwd, candidates: gather(t, agent)}
	}
	addRemote := func(agent *ice.Agent, remote signalled) {
		for _, raw := range remote.candidates {
			cand, err := ice.UnmarshalCandidate(raw)
			require.NoError(t, err)
			require.NoError(t, agent.AddRemoteCandidate(cand))
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()

	var wg sync.WaitGroup
	errs := make(chan error, 2*len(pairs))
	for _, p := range pairs {
		controlling, controlled := describe(p.controlling), describe(p.controlled)
		addRemote(p.controlling, controlled)
		addRemote(p.controlled, controlling)

		wg.Add(2)
		go func(agent *ice.Agent, remote signalled) {
			defer wg.Done()
			if _, err := agent.Dial(ctx, remote.ufrag, remote.pwd); err != nil {
				errs <- fmt.Errorf("dial: %w", err)
			}
		}(p.controlling, controlled)
		go func(agent *ice.Agent, remote signalled) {
			defer wg.Done()
			if _, err := agent.Accept(ctx, remote.ufrag, remote.pwd); err != nil {
				errs <- fmt.Errorf("accept: %w", err)
			}
		}(p.controlled, controlling)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		assert.NoError(t, err, "every agent must connect")
	}
}

// selectedTypes reports the local and remote candidate types of the selected pair.
func selectedTypes(t *testing.T, agent *ice.Agent) string {
	t.Helper()
	pair, err := agent.GetSelectedCandidatePair()
	require.NoError(t, err)
	if pair == nil {
		return "none"
	}
	return pair.Local.Type().String() + "/" + pair.Remote.Type().String()
}

// assertRouting checks the STUN deliveries a host observed: every response
// reaches only the conn that sent the request, and every request is read once
// and answered once.
func assertRouting(t *testing.T, name string, h *muxHost) {
	t.Helper()

	requests, responses := h.trace.counts()
	require.NotZero(t, requests, "%s must have received connectivity checks", name)
	require.NotZero(t, responses, "%s must have received responses", name)

	misdelivered := h.trace.responseMisdeliveries()
	assert.Empty(t, misdelivered, "%s: %d of %d responses not delivered to exactly the requesting conn", name, len(misdelivered), responses)

	duplicates := h.trace.requestDuplicates()
	assert.Empty(t, duplicates, "%s: %d of %d requests delivered or answered more than once", name, len(duplicates), requests)
}

// pairIDModes runs a scenario with peers that stamp the candidate pair ID, as
// the current fork does, and with peers that do not, as an upstream agent would.
var pairIDModes = []struct {
	name  string
	strip bool
}{
	{name: "with pair ID", strip: false},
	{name: "without pair ID", strip: true},
}

func TestRouting_HostAndSrflxOnOneMux(t *testing.T) {
	for _, mode := range pairIDModes {
		t.Run(mode.name, func(t *testing.T) {
			lab := newNATLab(t)
			hostA := newMuxHost(t, lab, lab.addNATedHost(t), mode.strip)
			hostB := newMuxHost(t, lab, lab.addNATedHost(t), mode.strip)
			lab.start(t)

			a, b := hostA.newAgent(t), hostB.newAgent(t)
			connect(t, []agentPair{{controlling: a, controlled: b}})
			t.Logf("selected pair (local/remote): controlling %s, controlled %s", selectedTypes(t, a), selectedTypes(t, b))

			assertRouting(t, "controlling host", hostA)
			assertRouting(t, "controlled host", hostB)
		})
	}
}

// TestRouting_OverlappingAgentsSameRemote models an agent being replaced while
// the old one is still open: both agents on each host talk to the same remote
// socket at the same time.
func TestRouting_OverlappingAgentsSameRemote(t *testing.T) {
	for _, mode := range pairIDModes {
		t.Run(mode.name, func(t *testing.T) {
			lab := newNATLab(t)
			hostA := newMuxHost(t, lab, lab.addNATedHost(t), mode.strip)
			hostB := newMuxHost(t, lab, lab.addNATedHost(t), mode.strip)
			lab.start(t)

			connect(t, []agentPair{
				{controlling: hostA.newAgent(t), controlled: hostB.newAgent(t)},
				{controlling: hostA.newAgent(t), controlled: hostB.newAgent(t)},
			})

			assertRouting(t, "host A", hostA)
			assertRouting(t, "host B", hostB)
		})
	}
}

func TestRouting_ManyAgentsPerMux(t *testing.T) {
	const agents = 20

	for _, mode := range pairIDModes {
		t.Run(mode.name, func(t *testing.T) {
			lab := newNATLab(t)
			hostA := newMuxHost(t, lab, lab.addNATedHost(t), mode.strip)
			hostB := newMuxHost(t, lab, lab.addNATedHost(t), mode.strip)
			lab.start(t)

			pairs := make([]agentPair, 0, agents)
			for i := 0; i < agents; i++ {
				// Alternate the roles so each mux serves controlling and controlled agents.
				if i%2 == 0 {
					pairs = append(pairs, agentPair{controlling: hostA.newAgent(t), controlled: hostB.newAgent(t)})
				} else {
					pairs = append(pairs, agentPair{controlling: hostB.newAgent(t), controlled: hostA.newAgent(t)})
				}
			}
			connect(t, pairs)

			assertRouting(t, "host A", hostA)
			assertRouting(t, "host B", hostB)
		})
	}
}

// TestRouting_MixedPairIDPeers connects one host to a peer whose STUN carries
// the candidate pair ID and to a peer whose STUN does not, at the same time.
func TestRouting_MixedPairIDPeers(t *testing.T) {
	lab := newNATLab(t)
	hostA := newMuxHost(t, lab, lab.addNATedHost(t), false)
	stamping := newMuxHost(t, lab, lab.addNATedHost(t), false)
	plain := newMuxHost(t, lab, lab.addNATedHost(t), true)
	lab.start(t)

	connect(t, []agentPair{
		{controlling: hostA.newAgent(t), controlled: stamping.newAgent(t)},
		{controlling: plain.newAgent(t), controlled: hostA.newAgent(t)},
	})

	assertRouting(t, "host A", hostA)
	assertRouting(t, "pair ID peer", stamping)
	assertRouting(t, "peer without pair ID", plain)
}

func quietLoggerFactory() logging.LoggerFactory {
	factory := logging.NewDefaultLoggerFactory()
	factory.DefaultLogLevel = logging.LogLevelError
	return factory
}

// TestUniversalUDPMux_ResponseFollowsRequest drives the mux over real sockets:
// two agents' conns have both sent to the same remote, which answers.
func TestUniversalUDPMux_ResponseFollowsRequest(t *testing.T) {
	mux, remote := newLoopbackMux(t)
	connA := getConn(t, mux, "ufragA")
	connB := getConn(t, mux, "ufragB")

	requestA := buildSTUN(t, stun.BindingRequest)
	requestB := buildSTUN(t, stun.BindingRequest)
	// connA retransmits its request with the same transaction ID.
	writeTo(t, connA, requestA.Raw, remote)
	writeTo(t, connA, requestA.Raw, remote)
	writeTo(t, connB, requestB.Raw, remote)
	for i := 0; i < 3; i++ {
		readFrom(t, remote)
	}

	reply(t, remote, mux, buildResponse(t, requestA))
	reply(t, remote, mux, buildResponse(t, requestB))
	assert.Equal(t, requestB.TransactionID, readSTUN(t, connB).TransactionID,
		"connB must not receive the response to connA's request")
	assert.Equal(t, requestA.TransactionID, readSTUN(t, connA).TransactionID,
		"connA receives the response to its retransmitted request")

	// A response nobody asked for keeps the address-based fallback: both conns
	// sent to this remote, so both receive it.
	unknown := buildResponse(t, buildSTUN(t, stun.BindingRequest))
	reply(t, remote, mux, unknown)
	assert.Equal(t, unknown.TransactionID, readSTUN(t, connA).TransactionID, "the fallback delivers to connA")
	assert.Equal(t, unknown.TransactionID, readSTUN(t, connB).TransactionID, "the fallback delivers to connB")
}

func TestUniversalUDPMux_RequestFollowsUsername(t *testing.T) {
	mux, remote := newLoopbackMux(t)
	connA := getConn(t, mux, "ufragA")
	connB := getConn(t, mux, "ufragB")

	// Both conns have sent to the remote, so both are registered for its address.
	writeTo(t, connA, buildSTUN(t, stun.BindingRequest).Raw, remote)
	writeTo(t, connB, buildSTUN(t, stun.BindingRequest).Raw, remote)
	readFrom(t, remote)
	readFrom(t, remote)

	forA := buildSTUN(t, stun.BindingRequest, stun.NewUsername("ufragA:remote"))
	forB := buildSTUN(t, stun.BindingRequest, stun.NewUsername("ufragB:remote"))
	reply(t, remote, mux, forA)
	reply(t, remote, mux, forB)

	assert.Equal(t, forB.TransactionID, readSTUN(t, connB).TransactionID, "connB must not receive connA's request")
	assert.Equal(t, forA.TransactionID, readSTUN(t, connA).TransactionID, "connA receives the request for its ufrag")
}

func newLoopbackMux(t *testing.T) (*UniversalUDPMuxDefault, *net.UDPConn) {
	t.Helper()

	mux := NewUniversalUDPMuxDefault(UniversalUDPMuxParams{UDPConn: listenUDP(t, net.IPv4(127, 0, 0, 1)), MTU: 1280})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		mux.ReadFromConn(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		_ = mux.Close()
		<-done
	})

	return mux, listenUDP(t, net.IPv4(127, 0, 0, 1))
}

func getConn(t *testing.T, mux *UniversalUDPMuxDefault, ufrag string) net.PacketConn {
	t.Helper()
	conn, err := mux.GetConn(ufrag, mux.LocalAddr(), "candidate-"+ufrag)
	require.NoError(t, err)
	return conn
}

func buildSTUN(t *testing.T, setters ...stun.Setter) *stun.Message {
	t.Helper()
	msg, err := stun.Build(append([]stun.Setter{stun.TransactionID}, setters...)...)
	require.NoError(t, err)
	return msg
}

func buildResponse(t *testing.T, request *stun.Message) *stun.Message {
	t.Helper()
	msg, err := stun.Build(request, stun.BindingSuccess)
	require.NoError(t, err)
	return msg
}

func writeTo(t *testing.T, conn net.PacketConn, b []byte, remote *net.UDPConn) {
	t.Helper()
	_, err := conn.WriteTo(b, remote.LocalAddr())
	require.NoError(t, err)
}

func readFrom(t *testing.T, remote *net.UDPConn) {
	t.Helper()
	require.NoError(t, remote.SetReadDeadline(time.Now().Add(5*time.Second)))
	buf := make([]byte, receiveMTU)
	_, _, err := remote.ReadFrom(buf)
	require.NoError(t, err)
}

// reply sends msg from the remote to the mux socket.
func reply(t *testing.T, remote *net.UDPConn, mux *UniversalUDPMuxDefault, msg *stun.Message) {
	t.Helper()
	_, err := remote.WriteTo(msg.Raw, mux.LocalAddr())
	require.NoError(t, err)
}

// readSTUN returns the next STUN message delivered to conn. Muxed conns ignore
// read deadlines, so the read runs in a goroutine bounded by a timer.
func readSTUN(t *testing.T, conn net.PacketConn) *stun.Message {
	t.Helper()

	type result struct {
		msg *stun.Message
		err error
	}
	ch := make(chan result, 1)
	go func() {
		buf := make([]byte, receiveMTU)
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			ch <- result{err: err}
			return
		}
		msg := &stun.Message{Raw: buf[:n]}
		ch <- result{msg: msg, err: msg.Decode()}
	}()

	select {
	case r := <-ch:
		require.NoError(t, r.err)
		return r.msg
	case <-time.After(5 * time.Second):
		t.Fatal("no STUN message delivered")
		return nil
	}
}
