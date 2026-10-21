package udpmux

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pion/stun/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSTUNTransactionResponses(t *testing.T) {
	for _, responseType := range []stun.MessageType{stun.BindingSuccess, stun.BindingError} {
		for _, pairID := range []string{"", "remote:host"} {
			t.Run(responseType.String()+"/pair="+pairID, func(t *testing.T) {
				mux, remote := newLifecycleTestMux(t)
				host := lifecycleTestConn(t, mux, "agent", "candidate:host")
				srflx := lifecycleTestConn(t, mux, "agentstun:example", "candidate:srflx")
				request := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
				otherRequest := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
				writeLifecycleTestPacket(t, host, otherRequest.Raw, remote)
				writeLifecycleTestPacket(t, srflx, request.Raw, remote)
				writeLifecycleTestPacket(t, srflx, request.Raw, remote)
				assert.Equal(t, 2, mux.transactions.pending(), "retransmission must reuse its transaction entry")

				response := stun.MustBuild(stun.NewTransactionIDSetter(request.TransactionID), responseType)
				if pairID != "" {
					response.Add(stun.AttrType(0x8100), []byte(pairID))
				}
				require.NoError(t, mux.HandleSTUNMessage(response, remote.LocalAddr()))
				assertLifecycleTestPacket(t, srflx, response.Raw)
				assert.Zero(t, host.buf.Count(), "the other local candidate must not receive the response")
				assert.Equal(t, 1, mux.transactions.pending(), "only the answered transaction is removed")
			})
		}
	}
}

func TestSTUNFailedResendPreservesOriginalResponse(t *testing.T) {
	mux, remote := newLifecycleTestMux(t)
	sender := lifecycleTestConn(t, mux, "sender", "candidate:sender")
	sibling := lifecycleTestConn(t, mux, "sibling", "candidate:sibling")
	request := buildSTUN(t, stun.BindingRequest)
	writeLifecycleTestPacket(t, sender, request.Raw, remote)
	writeLifecycleTestPacket(t, sibling, []byte("register address"), remote)

	require.NoError(t, mux.params.UDPConn.SetWriteDeadline(time.Now().Add(-time.Second)))
	_, err := sender.WriteTo(request.Raw, remote.LocalAddr())
	var timeout net.Error
	require.ErrorAs(t, err, &timeout)
	assert.True(t, timeout.Timeout(), "the retransmission must fail at the real socket's expired deadline")
	require.NoError(t, mux.params.UDPConn.SetWriteDeadline(time.Time{}))

	response := buildResponse(t, request)
	_, err = remote.WriteTo(response.Raw, mux.LocalAddr())
	require.NoError(t, err)
	require.NoError(t, mux.params.UDPConn.SetReadDeadline(time.Now().Add(time.Second)))
	buffer := make([]byte, receiveMTU)
	n, addr, err := mux.params.UDPConn.ReadFrom(buffer)
	require.NoError(t, err)
	incoming := &stun.Message{Raw: buffer[:n]}
	require.NoError(t, incoming.Decode())
	require.NoError(t, mux.HandleSTUNMessage(incoming, addr))

	assertLifecycleTestPacket(t, sender, response.Raw)
	assert.Zero(t, sibling.buf.Count(), "a failed resend must not broadcast the original request's response")
	assert.Zero(t, mux.transactions.pending(), "the original response must consume the outstanding request")
}

func TestSTUNTransactionHeaderClassification(t *testing.T) {
	request := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	malformedBody := append([]byte(nil), request.Raw...)
	malformedBody = append(malformedBody, 0, 6, 0xff, 0xff)
	binary.BigEndian.PutUint16(malformedBody[2:4], 4)
	reservedType := append([]byte(nil), request.Raw...)
	reservedType[0] |= 0xc0
	wrongCookie := append([]byte(nil), request.Raw...)
	wrongCookie[4] ^= 0xff
	truncated := append([]byte(nil), request.Raw...)
	binary.BigEndian.PutUint16(truncated[2:4], 4)
	unaligned := append(append([]byte(nil), request.Raw...), 0)
	binary.BigEndian.PutUint16(unaligned[2:4], 1)

	cases := []struct {
		name  string
		bytes []byte
		count int
	}{
		{name: "request", bytes: request.Raw, count: 1},
		{name: "indication", bytes: stun.MustBuild(stun.TransactionID, stun.NewType(stun.MethodBinding, stun.ClassIndication)).Raw},
		{name: "success", bytes: stun.MustBuild(stun.TransactionID, stun.BindingSuccess).Raw},
		{name: "error", bytes: stun.MustBuild(stun.TransactionID, stun.BindingError).Raw},
		{name: "short", bytes: request.Raw[:19]},
		{name: "reserved type bits", bytes: reservedType},
		{name: "wrong cookie", bytes: wrongCookie},
		{name: "truncated body", bytes: truncated},
		{name: "unaligned body", bytes: unaligned},
		{name: "not STUN", bytes: []byte("ordinary application packet")},
		{name: "header only parsing", bytes: malformedBody, count: 1},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			mux, remote := newLifecycleTestMux(t)
			conn := lifecycleTestConn(t, mux, "agent", "candidate")
			writeLifecycleTestPacket(t, conn, testCase.bytes, remote)
			assert.Equal(t, testCase.count, mux.transactions.pending(), "only request headers register transactions")
		})
	}
}

func TestSTUNTransactionExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mux, remote := newLifecycleTestMux(t)
		conn := lifecycleTestConn(t, mux, "agent", "candidate")
		request := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
		_, err := conn.WriteTo(request.Raw, remote.LocalAddr())
		require.NoError(t, err)
		require.Equal(t, 1, mux.transactions.pending(), "the request must be tracked before expiry")
		time.Sleep(2 * transactionTTL)
		synctest.Wait()
		assert.Zero(t, mux.transactions.pending(), "idle transactions must expire without another packet")
	})
}

func TestSTUNTransactionRemoval(t *testing.T) {
	for _, removal := range []string{"ufrag", "connection", "mux"} {
		t.Run(removal, func(t *testing.T) {
			mux, remote := newLifecycleTestMux(t)
			conn := lifecycleTestConn(t, mux, "agent", "candidate")
			request := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
			writeLifecycleTestPacket(t, conn, request.Raw, remote)
			switch removal {
			case "ufrag":
				mux.RemoveConnByUfrag("agent")
			case "connection":
				require.NoError(t, conn.Close())
			case "mux":
				require.NoError(t, mux.Close())
			}
			assert.Zero(t, mux.transactions.pending(), "removal must synchronously release pending transactions")
			assert.Zero(t, lifecycleTestAddressCount(mux), "removal must synchronously release address registrations")
			// A new destination forces a stale writer through address registration again.
			newRemote := listenUDP(t, net.IPv4(127, 0, 0, 1))
			if _, err := conn.WriteTo(request.Raw, newRemote.LocalAddr()); err != nil {
				assert.ErrorIs(t, err, io.ErrClosedPipe)
			}
			assert.Zero(t, mux.transactions.pending(), "a stale writer must not recreate removed transactions")
			assert.Zero(t, lifecycleTestAddressCount(mux), "a stale writer must not recreate address registrations")
		})
	}
}

func TestSTUNRemovedConnectionPreservesAddressFallback(t *testing.T) {
	mux, remote := newLifecycleTestMux(t)
	removed := lifecycleTestConn(t, mux, "removed", "old-candidate")
	survivor := lifecycleTestConn(t, mux, "survivor", "active-candidate")
	for _, conn := range []*udpMuxedConn{removed, survivor} {
		writeLifecycleTestPacket(t, conn, []byte("register address"), remote)
	}
	mux.RemoveConnByUfrag("removed")
	response := stun.MustBuild(stun.TransactionID, stun.BindingSuccess)
	require.NoError(t, mux.HandleSTUNMessage(response, remote.LocalAddr()))
	assertLifecycleTestPacket(t, survivor, response.Raw)
	assert.Zero(t, removed.buf.Count(), "removed connections must not receive fallback traffic")
}

func TestSTUNClosedConnectionPreservesReplacement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mux, remote := newLifecycleTestMux(t)
		old := lifecycleTestConn(t, mux, "agent", "old-candidate")
		mux.RemoveConnByUfrag("agent")
		replacement := lifecycleTestConn(t, mux, "agent", "new-candidate")
		require.NoError(t, old.Close())
		synctest.Wait()
		incoming := buildSTUN(t, stun.BindingRequest, stun.NewUsername("agent:remote"))
		require.NoError(t, mux.HandleSTUNMessage(incoming, remote.LocalAddr()))
		assertLifecycleTestPacket(t, replacement, incoming.Raw)
		request := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
		_, err := replacement.WriteTo(request.Raw, remote.LocalAddr())
		require.NoError(t, err)
		require.Equal(t, 1, mux.transactions.pending(), "closing an old connection must not unregister its replacement")
		response := stun.MustBuild(stun.NewTransactionIDSetter(request.TransactionID), stun.BindingSuccess)
		require.NoError(t, mux.HandleSTUNMessage(response, remote.LocalAddr()))
		assertLifecycleTestPacket(t, replacement, response.Raw)
		assert.Zero(t, mux.transactions.pending(), "the replacement must remain registered and consume its response")
	})
}

func TestSTUNConcurrentFirstWritesRegisterOnce(t *testing.T) {
	mux, _ := newLifecycleTestMux(t)
	conn := lifecycleTestConn(t, mux, "agent", "candidate")
	for attempt := 0; attempt < 20; attempt++ {
		remote := listenUDP(t, net.IPv4(127, 0, 0, 1))
		var writers sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < 32; i++ {
			writers.Go(func() {
				<-start
				_, err := conn.WriteTo([]byte("register address"), remote.LocalAddr())
				assert.NoError(t, err)
			})
		}
		close(start)
		writers.Wait()
		response := stun.MustBuild(stun.TransactionID, stun.BindingSuccess)
		require.NoError(t, mux.HandleSTUNMessage(response, remote.LocalAddr()))
		assertLifecycleTestPacket(t, conn, response.Raw)
	}
}

func TestSTUNMuxCloseReleasesRoutingState(t *testing.T) {
	mux, remote := newLifecycleTestMux(t)
	conn := lifecycleTestConn(t, mux, "agent", "candidate")
	request := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	writeLifecycleTestPacket(t, conn, request.Raw, remote)
	require.Equal(t, 1, mux.transactions.pending(), "the transaction must be registered before closing")
	require.Equal(t, 1, lifecycleTestAddressCount(mux), "the address must be registered before closing")
	require.NoError(t, mux.Close())

	mux.mu.Lock()
	connections := len(mux.connsIPv4) + len(mux.connsIPv6)
	candidates := len(mux.candidateConnMap)
	mux.mu.Unlock()
	mux.transactions.mu.Lock()
	transactions := len(mux.transactions.entries)
	transactionOrder := len(mux.transactions.queue)
	mux.transactions.mu.Unlock()
	assert.Zero(t, connections, "Close must release registered connections")
	assert.Zero(t, candidates, "Close must release candidate registrations")
	assert.Zero(t, transactions, "Close must release pending transactions")
	assert.Zero(t, transactionOrder, "Close must release transaction expiry bookkeeping")
	assert.Zero(t, lifecycleTestAddressCount(mux), "Close must release addresses synchronously")
	require.NoError(t, mux.Close(), "Close must be idempotent")
}

func TestSTUNTransactionConcurrentRemoval(t *testing.T) {
	mux, remote := newLifecycleTestMux(t)
	var writers sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 20; i++ {
		key := fmt.Sprintf("agent-%d", i)
		conn := lifecycleTestConn(t, mux, key, key)
		writers.Go(func() {
			<-start
			for j := 0; j < 20; j++ {
				request := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
				if _, err := conn.WriteTo(request.Raw, remote.LocalAddr()); err != nil {
					assert.ErrorIs(t, err, io.ErrClosedPipe)
					return
				}
				response := stun.MustBuild(stun.NewTransactionIDSetter(request.TransactionID), stun.BindingSuccess)
				if err := mux.HandleSTUNMessage(response, remote.LocalAddr()); err != nil {
					assert.ErrorIs(t, err, io.ErrClosedPipe)
				}
			}
		})
		writers.Go(func() {
			<-start
			mux.RemoveConnByUfrag(key)
			assert.NoError(t, conn.Close())
		})
	}
	close(start)
	writers.Wait()
	assert.Zero(t, mux.transactions.pending(), "concurrent writers and removal must not retain stale transactions")
	assert.Zero(t, lifecycleTestAddressCount(mux), "concurrent writers and removal must not retain stale addresses")
}

func newLifecycleTestMux(t *testing.T) (*SingleSocketUDPMux, *net.UDPConn) {
	t.Helper()
	local := listenUDP(t, net.IPv4(127, 0, 0, 1))
	remote := listenUDP(t, net.IPv4(127, 0, 0, 1))
	mux := NewSingleSocketUDPMux(Params{UDPConn: local})
	t.Cleanup(func() { assert.NoError(t, mux.Close()) })
	return mux, remote
}

func lifecycleTestConn(t *testing.T, mux *SingleSocketUDPMux, key, candidate string) *udpMuxedConn {
	t.Helper()
	conn, err := mux.GetConn(key, mux.LocalAddr(), candidate)
	require.NoError(t, err)
	muxed, ok := conn.(*udpMuxedConn)
	require.True(t, ok, "GetConn must return the mux's real connection")
	t.Cleanup(func() { assert.NoError(t, muxed.Close()) })
	return muxed
}

func writeLifecycleTestPacket(t *testing.T, conn *udpMuxedConn, packet []byte, remote *net.UDPConn) {
	t.Helper()
	n, err := conn.WriteTo(packet, remote.LocalAddr())
	require.NoError(t, err)
	require.Equal(t, len(packet), n, "the whole request must be written")
	require.NoError(t, remote.SetReadDeadline(time.Now().Add(time.Second)))
	buffer := make([]byte, receiveMTU)
	n, _, err = remote.ReadFrom(buffer)
	require.NoError(t, err)
	assert.Equal(t, packet, buffer[:n], "the real socket must receive the original datagram")
}

func assertLifecycleTestPacket(t *testing.T, conn *udpMuxedConn, packet []byte) {
	t.Helper()
	require.Equal(t, 1, conn.buf.Count(), "the destination must receive exactly one datagram")
	buffer := make([]byte, receiveMTU)
	n, _, err := conn.ReadFrom(buffer)
	require.NoError(t, err)
	assert.Equal(t, packet, buffer[:n], "the selected connection must receive the original STUN datagram")
}

func lifecycleTestAddressCount(mux *SingleSocketUDPMux) int {
	mux.addressMapMu.RLock()
	defer mux.addressMapMu.RUnlock()
	return len(mux.addressMap)
}
