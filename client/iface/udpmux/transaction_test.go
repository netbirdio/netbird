package udpmux

import (
	"encoding/binary"
	"fmt"
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
		t.Run(responseType.String(), func(t *testing.T) {
			mux, remote := newTransactionTestMux(t)
			host := transactionTestConn(t, mux, "agent", "host")
			srflx := transactionTestConn(t, mux, "agentstun:example", "srflx")
			request := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
			otherRequest := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
			writeTransactionTestPacket(t, host, otherRequest.Raw, remote)
			writeTransactionTestPacket(t, srflx, request.Raw, remote)
			writeTransactionTestPacket(t, srflx, request.Raw, remote)
			assert.Equal(t, 2, transactionTestCount(mux), "retransmission must reuse its transaction entry")

			response := stun.MustBuild(stun.NewTransactionIDSetter(request.TransactionID), responseType)
			response.Add(stun.AttrType(0x8100), []byte("remote:host"))
			require.NoError(t, mux.HandleSTUNMessage(response, remote.LocalAddr()))
			assertTransactionTestPacket(t, srflx, response.Raw)
			assert.Zero(t, host.buf.Count(), "the other local candidate must not receive the response")
			assert.Equal(t, 1, transactionTestCount(mux), "only the answered transaction is removed")
		})
	}
}

func TestSTUNRequestUsernameRouting(t *testing.T) {
	for _, messageType := range []stun.MessageType{stun.BindingRequest, stun.NewType(stun.MethodBinding, stun.ClassIndication)} {
		t.Run(messageType.String(), func(t *testing.T) {
			mux, remote := newTransactionTestMux(t)
			host := transactionTestConn(t, mux, "agent", "host")
			srflx := transactionTestConn(t, mux, "agentstun:example", "srflx")
			other := transactionTestConn(t, mux, "other", "other-host")
			for _, conn := range []*udpMuxedConn{host, srflx, other} {
				writeTransactionTestPacket(t, conn, []byte("register address"), remote)
			}
			request := stun.MustBuild(stun.TransactionID, messageType, stun.NewUsername("agent:remote"))
			require.NoError(t, mux.HandleSTUNMessage(request, remote.LocalAddr()))
			assertTransactionTestPacket(t, host, request.Raw)
			assert.Zero(t, srflx.buf.Count(), "the srflx connection must not receive a request without a pair ID")
			assert.Zero(t, other.buf.Count(), "another agent at the same address must not receive the request")
		})
	}
}

func TestSTUNUnknownTransactionFallsBackToAddress(t *testing.T) {
	mux, remote := newTransactionTestMux(t)
	first := transactionTestConn(t, mux, "first", "first-host")
	second := transactionTestConn(t, mux, "second", "second-host")
	for _, conn := range []*udpMuxedConn{first, second} {
		writeTransactionTestPacket(t, conn, []byte("register address"), remote)
	}
	response := stun.MustBuild(stun.TransactionID, stun.BindingSuccess)
	require.NoError(t, mux.HandleSTUNMessage(response, remote.LocalAddr()))
	assertTransactionTestPacket(t, first, response.Raw)
	assertTransactionTestPacket(t, second, response.Raw)
}

func TestSTUNTransactionHeaderClassification(t *testing.T) {
	request := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	malformedBody := append([]byte(nil), request.Raw...)
	malformedBody = append(malformedBody, 0, 6, 0xff, 0xff)
	binary.BigEndian.PutUint16(malformedBody[2:4], 4)

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
		{name: "not STUN", bytes: []byte("ordinary application packet")},
		{name: "header only parsing", bytes: malformedBody, count: 1},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			mux, remote := newTransactionTestMux(t)
			conn := transactionTestConn(t, mux, "agent", "candidate")
			writeTransactionTestPacket(t, conn, testCase.bytes, remote)
			assert.Equal(t, testCase.count, transactionTestCount(mux), "only request headers register transactions")
		})
	}
}

func TestSTUNTransactionWriteError(t *testing.T) {
	mux, _ := newTransactionTestMux(t)
	conn := transactionTestConn(t, mux, "agent", "candidate")
	request := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	_, err := conn.WriteTo(request.Raw, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	require.Error(t, err, "port zero must reject the outgoing datagram")
	assert.Zero(t, transactionTestCount(mux), "an unsuccessful write must not retain a transaction")
}

func TestSTUNTransactionExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mux, remote := newTransactionTestMux(t)
		conn := transactionTestConn(t, mux, "agent", "candidate")
		request := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
		_, err := conn.WriteTo(request.Raw, remote.LocalAddr())
		require.NoError(t, err)
		require.Equal(t, 1, transactionTestCount(mux), "the request must be tracked before expiry")
		time.Sleep(2 * stunTransactionTTL)
		synctest.Wait()
		assert.Zero(t, transactionTestCount(mux), "idle transactions must expire without another packet")
	})
}

func TestSTUNTransactionBounded(t *testing.T) {
	mux, remote := newTransactionTestMux(t)
	conn := transactionTestConn(t, mux, "agent", "candidate")
	first := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	_, err := conn.WriteTo(first.Raw, remote.LocalAddr())
	require.NoError(t, err)
	for i := 0; i < maxSTUNTransactions; i++ {
		request := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
		_, err := conn.WriteTo(request.Raw, remote.LocalAddr())
		require.NoError(t, err)
	}
	assert.Equal(t, maxSTUNTransactions, transactionTestCount(mux), "unanswered requests must have a fixed memory bound")
	assert.Nil(t, mux.takeSTUNTransaction(first.TransactionID), "the oldest request must be evicted at capacity")
}

func TestSTUNTransactionRemoval(t *testing.T) {
	for _, removal := range []string{"ufrag", "connection", "mux"} {
		t.Run(removal, func(t *testing.T) {
			mux, remote := newTransactionTestMux(t)
			conn := transactionTestConn(t, mux, "agent", "candidate")
			request := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
			writeTransactionTestPacket(t, conn, request.Raw, remote)
			switch removal {
			case "ufrag":
				mux.RemoveConnByUfrag("agent")
			case "connection":
				require.NoError(t, conn.Close())
			case "mux":
				require.NoError(t, mux.Close())
			}
			assert.Zero(t, transactionTestCount(mux), "removal must synchronously release pending transactions")
			// A caller can retain a connection after the mux removes it.
			_, _ = conn.WriteTo(request.Raw, remote.LocalAddr())
			assert.Zero(t, transactionTestCount(mux), "a stale writer must not recreate removed transactions")
		})
	}
}

func TestSTUNRemovedConnectionPreservesAddressFallback(t *testing.T) {
	mux, remote := newTransactionTestMux(t)
	removed := transactionTestConn(t, mux, "removed", "old-candidate")
	survivor := transactionTestConn(t, mux, "survivor", "active-candidate")
	for _, conn := range []*udpMuxedConn{removed, survivor} {
		writeTransactionTestPacket(t, conn, []byte("register address"), remote)
	}
	mux.RemoveConnByUfrag("removed")
	response := stun.MustBuild(stun.TransactionID, stun.BindingSuccess)
	require.NoError(t, mux.HandleSTUNMessage(response, remote.LocalAddr()))
	assertTransactionTestPacket(t, survivor, response.Raw)
	assert.Zero(t, removed.buf.Count(), "removed connections must not receive fallback traffic")
}

func TestSTUNClosedConnectionPreservesReplacement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mux, remote := newTransactionTestMux(t)
		old := transactionTestConn(t, mux, "agent", "old-candidate")
		mux.RemoveConnByUfrag("agent")
		replacement := transactionTestConn(t, mux, "agent", "new-candidate")
		require.NoError(t, old.Close())
		synctest.Wait()
		request := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
		_, err := replacement.WriteTo(request.Raw, remote.LocalAddr())
		require.NoError(t, err)
		response := stun.MustBuild(stun.NewTransactionIDSetter(request.TransactionID), stun.BindingSuccess)
		require.NoError(t, mux.HandleSTUNMessage(response, remote.LocalAddr()))
		assertTransactionTestPacket(t, replacement, response.Raw)
		assert.Zero(t, transactionTestCount(mux), "the replacement must remain registered and consume its response")
	})
}

func TestSTUNTransactionConcurrentRemoval(t *testing.T) {
	mux, remote := newTransactionTestMux(t)
	var writers sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 20; i++ {
		key := fmt.Sprintf("agent-%d", i)
		conn := transactionTestConn(t, mux, key, key)
		writers.Go(func() {
			<-start
			for j := 0; j < 20; j++ {
				request := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
				if _, err := conn.WriteTo(request.Raw, remote.LocalAddr()); err != nil {
					return
				}
				response := stun.MustBuild(stun.NewTransactionIDSetter(request.TransactionID), stun.BindingSuccess)
				_ = mux.HandleSTUNMessage(response, remote.LocalAddr())
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
	assert.Zero(t, transactionTestCount(mux), "concurrent writers and removal must not retain stale transactions")
}

func newTransactionTestMux(t *testing.T) (*SingleSocketUDPMux, *net.UDPConn) {
	t.Helper()
	local := listenUDP(t, net.IPv4(127, 0, 0, 1))
	remote := listenUDP(t, net.IPv4(127, 0, 0, 1))
	mux := NewSingleSocketUDPMux(Params{UDPConn: local})
	t.Cleanup(func() { assert.NoError(t, mux.Close()) })
	return mux, remote
}

func transactionTestConn(t *testing.T, mux *SingleSocketUDPMux, key, candidate string) *udpMuxedConn {
	t.Helper()
	conn, err := mux.GetConn(key, mux.LocalAddr(), candidate)
	require.NoError(t, err)
	muxed, ok := conn.(*udpMuxedConn)
	require.True(t, ok, "GetConn must return the mux's real connection")
	t.Cleanup(func() { assert.NoError(t, muxed.Close()) })
	return muxed
}

func writeTransactionTestPacket(t *testing.T, conn *udpMuxedConn, packet []byte, remote *net.UDPConn) {
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

func assertTransactionTestPacket(t *testing.T, conn *udpMuxedConn, packet []byte) {
	t.Helper()
	require.Equal(t, 1, conn.buf.Count(), "the destination must receive exactly one datagram")
	buffer := make([]byte, receiveMTU)
	n, _, err := conn.ReadFrom(buffer)
	require.NoError(t, err)
	assert.Equal(t, packet, buffer[:n], "the selected connection must receive the original STUN datagram")
}

func transactionTestCount(mux *SingleSocketUDPMux) int {
	mux.mu.Lock()
	defer mux.mu.Unlock()
	return len(mux.transactions)
}
