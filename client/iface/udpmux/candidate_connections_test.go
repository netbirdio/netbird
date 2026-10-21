package udpmux

import (
	"io"
	"net"
	"testing"

	"github.com/pion/stun/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCandidateConnectionsIdentity(t *testing.T) {
	for _, candidateIDs := range [][2]string{{"first", "second"}, {"", ""}} {
		t.Run(candidateIDs[0], func(t *testing.T) {
			local := listenUDP(t, net.IPv4zero)
			mux := NewSingleSocketUDPMux(Params{UDPConn: local})
			t.Cleanup(func() { assert.NoError(t, mux.Close()) })
			port := local.LocalAddr().(*net.UDPAddr).Port
			firstAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
			secondAddr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: port}
			first, err := mux.GetConn("agent", firstAddr, candidateIDs[0])
			require.NoError(t, err)
			second, err := mux.GetConn("agent", secondAddr, candidateIDs[1])
			require.NoError(t, err)
			require.NotSame(t, first, second, "different host candidates must not compete for one read queue")
			firstAgain, err := mux.GetConn("agent", firstAddr, candidateIDs[0])
			require.NoError(t, err)
			assert.Same(t, first, firstAgain, "repeated access to one candidate must reuse its queue")
			secondAgain, err := mux.GetConn("agent", secondAddr, candidateIDs[1])
			require.NoError(t, err)
			assert.Same(t, second, secondAgain)
			assert.Equal(t, local.LocalAddr(), first.LocalAddr(), "the shared socket address remains unchanged")
			assert.Equal(t, local.LocalAddr(), second.LocalAddr())
		})
	}
}

func TestCandidateConnectionsRoutingAndRemoval(t *testing.T) {
	mux, remote := newLifecycleTestMux(t)
	first := lifecycleTestConn(t, mux, "agent", "candidate:first")
	second := lifecycleTestConn(t, mux, "agent", "candidate:second")
	require.NotSame(t, first, second)
	firstRequest := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	secondRequest := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	writeLifecycleTestPacket(t, first, firstRequest.Raw, remote)
	writeLifecycleTestPacket(t, second, secondRequest.Raw, remote)

	request := stun.MustBuild(stun.TransactionID, stun.BindingRequest, stun.NewUsername("agent:remote"))
	require.NoError(t, mux.HandleSTUNMessage(request, remote.LocalAddr()))
	assertLifecycleTestPacket(t, first, request.Raw)
	assert.Zero(t, second.buf.Count(), "USERNAME-only requests retain the first host recipient")
	request.Add(stun.AttrType(0x8100), []byte("remote:second"))
	require.NoError(t, mux.HandleSTUNMessage(request, remote.LocalAddr()))
	assertLifecycleTestPacket(t, second, request.Raw)
	assert.Zero(t, first.buf.Count(), "pair-ID requests target the matching candidate queue")

	response := buildResponse(t, secondRequest)
	require.NoError(t, mux.HandleSTUNMessage(response, remote.LocalAddr()))
	assertLifecycleTestPacket(t, second, response.Raw)
	assert.Zero(t, first.buf.Count(), "known responses must return to the sending candidate")

	unknownResponse := stun.MustBuild(stun.TransactionID, stun.BindingSuccess)
	require.NoError(t, mux.HandleSTUNMessage(unknownResponse, remote.LocalAddr()))
	assertLifecycleTestPacket(t, first, unknownResponse.Raw)
	assertLifecycleTestPacket(t, second, unknownResponse.Raw)

	survivorRequest := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	writeLifecycleTestPacket(t, second, survivorRequest.Raw, remote)
	require.NoError(t, first.Close())
	assert.Equal(t, 1, mux.transactions.pending(), "closing a candidate must retain its sibling's pending request")
	assert.False(t, second.isClosed(), "closing a host candidate must not close its sibling")
	response = buildResponse(t, survivorRequest)
	require.NoError(t, mux.HandleSTUNMessage(response, remote.LocalAddr()))
	assertLifecycleTestPacket(t, second, response.Raw)
	assert.Zero(t, mux.transactions.pending())
	request = stun.MustBuild(stun.TransactionID, stun.BindingRequest, stun.NewUsername("agent:remote"))
	require.NoError(t, mux.HandleSTUNMessage(request, remote.LocalAddr()))
	assertLifecycleTestPacket(t, second, request.Raw)
	writeLifecycleTestPacket(t, second, secondRequest.Raw, remote)
	mux.RemoveConnByUfrag("agent")
	assert.Zero(t, mux.transactions.pending())
	assert.Zero(t, lifecycleTestAddressCount(mux))
	_, err := second.WriteTo(secondRequest.Raw, remote.LocalAddr())
	assert.ErrorIs(t, err, io.ErrClosedPipe, "a removed child must not recreate routing state")

	replacement := lifecycleTestConn(t, mux, "agent", "candidate:second")
	require.NoError(t, second.Close())
	require.NoError(t, mux.HandleSTUNMessage(request, remote.LocalAddr()))
	assertLifecycleTestPacket(t, replacement, request.Raw)
}

func TestCandidateConnectionsRemoveBothFamilies(t *testing.T) {
	local := listenUDP(t, net.IPv4zero)
	mux := NewSingleSocketUDPMux(Params{UDPConn: local})
	t.Cleanup(func() { assert.NoError(t, mux.Close()) })
	port := local.LocalAddr().(*net.UDPAddr).Port
	var connections []net.PacketConn
	for i, ip := range []net.IP{net.IPv4(127, 0, 0, 1), net.IPv4(192, 0, 2, 1), net.IPv6loopback} {
		conn, err := mux.GetConn("agent", &net.UDPAddr{IP: ip, Port: port}, string(rune('a'+i)))
		require.NoError(t, err)
		connections = append(connections, conn)
		t.Cleanup(func() { assert.NoError(t, conn.Close()) })
	}
	mux.RemoveConnByUfrag("agent")
	mux.mu.Lock()
	assert.Empty(t, mux.connsIPv4)
	assert.Empty(t, mux.connsIPv6)
	assert.Empty(t, mux.candidateConnMap)
	mux.mu.Unlock()
	for _, conn := range connections {
		_, err := conn.WriteTo([]byte("removed"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		assert.ErrorIs(t, err, io.ErrClosedPipe)
	}
}
