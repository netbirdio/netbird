package sharedsock

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/pion/stun/v2"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

func TestShouldReadSTUNOnReadFrom(t *testing.T) {

	// create raw socket on a port
	testingPort := 51821
	rawSock, err := Listen(testingPort, NewIncomingSTUNFilter())
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
	rawSock, err := Listen(testingPort, NewIncomingSTUNFilter())
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
	rawSock, err := Listen(testingPort, NewIncomingSTUNFilter())
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

func TestSharedSocket_Close(t *testing.T) {
	rawSock, err := Listen(39440, NewIncomingSTUNFilter())
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
