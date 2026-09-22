//go:build privileged

package sharedsock

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/mdlayher/socket"
	"github.com/pion/stun/v2"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
)

func TestShouldReadSTUNOnReadFrom(t *testing.T) {

	// create raw socket on a port
	testingPort := 51821
	rawSock, err := Listen(testingPort, NewIncomingSTUNFilter(), 1280)
	require.NoError(t, err, "received an error while creating STUN listener, error: %s", err)
	err = rawSock.SetReadDeadline(time.Now().Add(3 * time.Second))
	require.NoError(t, err, "unable to set deadline, error: %s", err)

	wg := sync.WaitGroup{}
	wg.Add(1)

	// when reading from the raw socket
	buf := make([]byte, 1500)
	rcvMSG := &stun.Message{
		Raw: buf,
	}
	ctx, cancel := context.WithTimeout(context.TODO(), 10*time.Second)
	defer cancel()

	go func() {
		select {
		case <-ctx.Done():
			return
		default:
			_, _, err := rawSock.ReadFrom(buf)
			if err != nil {
				log.Errorf("error while reading packet %s", err)
				return
			}

			err = rcvMSG.Decode()
			if err != nil {
				log.Warnf("error while parsing STUN message. The packet doesn't seem to be a STUN packet: %s", err)
				return
			}
			wg.Done()
		}

	}()

	// and sending STUN packet to the shared port, the packet has to be handled
	udpListener, err := net.ListenUDP("udp", &net.UDPAddr{Port: 12345, IP: net.ParseIP("127.0.0.1")})
	require.NoError(t, err, "received an error while creating regular listener, error: %s", err)
	defer udpListener.Close()
	stunMSG, err := stun.Build(stun.NewType(stun.MethodBinding, stun.ClassRequest), stun.TransactionID,
		stun.Fingerprint,
	)
	require.NoError(t, err, "unable to build stun msg, error: %s", err)
	_, err = udpListener.WriteTo(stunMSG.Raw, net.UDPAddrFromAddrPort(netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", testingPort))))
	require.NoError(t, err, "received an error while writing the stun listener, error: %s", err)

	// the packet has to be handled and be a STUN packet
	wg.Wait()
	require.EqualValues(t, stunMSG.TransactionID, rcvMSG.TransactionID, "transaction id values did't match")
}

func TestShouldNotReadNonSTUNPackets(t *testing.T) {
	testingPort := 39439
	rawSock, err := Listen(testingPort, NewIncomingSTUNFilter(), 1280)
	require.NoError(t, err, "received an error while creating STUN listener, error: %s", err)
	defer rawSock.Close()

	buf := make([]byte, 1500)
	err = rawSock.SetReadDeadline(time.Now().Add(time.Second))
	require.NoError(t, err, "unable to set deadline, error: %s", err)

	errGrp := errgroup.Group{}
	errGrp.Go(func() error {
		_, _, err := rawSock.ReadFrom(buf)
		return err
	})
	nonStun := []byte("netbird")
	udpListener, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0, IP: net.ParseIP("127.0.0.1")})
	require.NoError(t, err, "received an error while creating regular listener, error: %s", err)
	defer udpListener.Close()
	remote := net.UDPAddrFromAddrPort(netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", testingPort)))
	_, err = udpListener.WriteTo(nonStun, remote)
	require.NoError(t, err, "received an error while writing the stun listener, error: %s", err)

	err = errGrp.Wait()
	require.Error(t, err, "should receive an error")
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("error should be I/O timeout, got: %s", err)
	}
}

func TestWriteTo(t *testing.T) {
	udpListener, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 0, IP: net.ParseIP("127.0.0.1")})
	require.NoError(t, err, "received an error while creating regular listener, error: %s", err)
	defer udpListener.Close()

	testingPort := 39440
	rawSock, err := Listen(testingPort, NewIncomingSTUNFilter(), 1280)
	require.NoError(t, err, "received an error while creating STUN listener, error: %s", err)
	defer rawSock.Close()

	buf := make([]byte, 1500)
	err = udpListener.SetReadDeadline(time.Now().Add(3 * time.Second))
	require.NoError(t, err, "unable to set deadline, error: %s", err)

	errGrp := errgroup.Group{}
	var remoteAdr net.Addr
	var rcvBytes int
	errGrp.Go(func() error {
		n, a, err := udpListener.ReadFrom(buf)
		remoteAdr = a
		rcvBytes = n
		return err
	})

	msg := []byte("netbird")
	_, err = rawSock.WriteTo(msg, udpListener.LocalAddr())
	require.NoError(t, err, "received an error while writing the stun listener, error: %s", err)

	err = errGrp.Wait()
	require.NoError(t, err, "received an error while reading the packet, error: %s", err)

	require.EqualValues(t, string(msg), string(buf[:rcvBytes]), "received message should match")

	udpRcv, ok := remoteAdr.(*net.UDPAddr)
	require.True(t, ok, "udp address conversion didn't work")

	require.EqualValues(t, testingPort, udpRcv.Port, "received address port didn't match")
}

// TestWriteTo6KernelChecksum checks that an IPv6 packet leaves the raw socket with a
// valid UDP checksum. writeTo6 serializes the checksum as zero and relies on the kernel
// (IPV6_CHECKSUM) to fill it in. Without the socket option the zero checksum makes the
// listener drop the packet. A second raw socket captures the packet over lo so the test
// checks the checksum value itself, not only that the receive path accepted it.
func TestWriteTo6KernelChecksum(t *testing.T) {
	loopback := netip.IPv6Loopback()
	udpListener, err := net.ListenUDP("udp6", &net.UDPAddr{IP: loopback.AsSlice()})
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	defer udpListener.Close()
	listenerPort := udpListener.LocalAddr().(*net.UDPAddr).Port

	capture, err := socket.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_UDP, "capture_udp6", nil)
	require.NoError(t, err, "create capture socket")
	defer capture.Close()

	testingPort := 39441
	rawSock, err := Listen(testingPort, NewIncomingSTUNFilter(), 1280)
	require.NoError(t, err, "create shared socket")
	defer rawSock.Close()

	msg := []byte("netbird")
	_, err = rawSock.WriteTo(msg, udpListener.LocalAddr())
	require.NoError(t, err, "write to IPv6 listener")

	require.NoError(t, udpListener.SetReadDeadline(time.Now().Add(3*time.Second)))
	buf := make([]byte, 1500)
	n, from, err := udpListener.ReadFrom(buf)
	require.NoError(t, err, "read from IPv6 listener")
	assert.Equal(t, string(msg), string(buf[:n]), "payload should arrive intact")
	assert.Equal(t, testingPort, from.(*net.UDPAddr).Port, "source port should be the shared port")

	segment := readUDP6Segment(t, capture, uint16(listenerPort))
	assert.NotZero(t, binary.BigEndian.Uint16(segment[udpChecksumOffset:]), "checksum should be filled in")
	assert.True(t, udp6ChecksumValid(loopback, loopback, segment), "checksum should verify against the pseudo-header")
}

// readUDP6Segment returns the first UDP segment the capture socket sees for dstPort.
// IPv6 raw sockets deliver the transport header without the IP header.
func readUDP6Segment(t *testing.T, capture *socket.Conn, dstPort uint16) []byte {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	buf := make([]byte, 1500)
	for {
		n, _, err := capture.Recvfrom(ctx, buf, 0)
		require.NoError(t, err, "capture IPv6 packet")
		if n >= 8 && binary.BigEndian.Uint16(buf[2:4]) == dstPort {
			return append([]byte(nil), buf[:n]...)
		}
	}
}

// udp6ChecksumValid verifies a UDP segment's checksum over the RFC 8200 section 8.1
// pseudo-header.
func udp6ChecksumValid(src, dst netip.Addr, segment []byte) bool {
	var sum uint32
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i:]))
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}

	src16, dst16 := src.As16(), dst.As16()
	add(src16[:])
	add(dst16[:])
	var lenNext [8]byte
	binary.BigEndian.PutUint32(lenNext[:4], uint32(len(segment)))
	lenNext[7] = unix.IPPROTO_UDP
	add(lenNext[:])
	add(segment)

	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return sum == 0xffff
}

func TestSharedSocket_Close(t *testing.T) {
	rawSock, err := Listen(39440, NewIncomingSTUNFilter(), 1280)
	require.NoError(t, err, "received an error while creating STUN listener, error: %s", err)

	errGrp := errgroup.Group{}

	errGrp.Go(func() error {
		buf := make([]byte, 1500)
		_, _, err := rawSock.ReadFrom(buf)
		return err
	})
	_ = rawSock.Close()
	err = errGrp.Wait()
	if err != ErrSharedSockStopped {
		t.Errorf("invalid error response: %s", err)
	}
}
