package stunlistener

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

	"github.com/pion/stun"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/netbirdio/netbird/iface/bind"
)

func TestReadStun(t *testing.T) {
	var rcvMSG *stun.Message
	wg := sync.WaitGroup{}
	stunHandler := func(msg *stun.Message, addr net.Addr) error {
		rcvMSG = msg
		wg.Done()
		return nil
	}

	udpListener, err := net.ListenUDP("udp", &net.UDPAddr{Port: 12345, IP: net.ParseIP("127.0.0.1")})
	require.NoError(t, err, "received an error while creating regular listener, error: %s", err)
	defer udpListener.Close()

	testingPort := 51821
	ctx, cancel := context.WithTimeout(context.TODO(), 10*time.Second)
	defer cancel()
	s, err := NewSTUNListener(ctx, testingPort)
	require.NoError(t, err, "received an error while creating stun listener, error: %s", err)

	wg.Add(1)
	err = s.Listen(stunHandler)
	require.NoError(t, err, "received an error while listening on STUN packets, error: %s", err)
	defer s.Close()

	stunMSG, err := stun.Build(stun.NewType(stun.MethodBinding, stun.ClassRequest), stun.TransactionID,
		stun.Fingerprint,
	)
	require.NoError(t, err, "unable to build stun msg, error: %s", err)

	_, err = udpListener.WriteTo(stunMSG.Raw, net.UDPAddrFromAddrPort(netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", testingPort))))
	require.NoError(t, err, "received an error while writing the stun listener, error: %s", err)
	wg.Wait()
	require.EqualValues(t, stunMSG.TransactionID, rcvMSG.TransactionID, "transaction id values did't match")
}

func TestReadNONStun(t *testing.T) {
	udpListener, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0, IP: net.ParseIP("127.0.0.1")})
	require.NoError(t, err, "received an error while creating regular listener, error: %s", err)
	defer udpListener.Close()

	testingPort := 39439
	ctx, cancel := context.WithTimeout(context.TODO(), 10*time.Second)
	defer cancel()
	s, err := NewSTUNListener(ctx, testingPort)
	require.NoError(t, err, "received an error while creating stun listener, error: %s", err)
	mux := bind.NewUniversalUDPMuxDefault(bind.UniversalUDPMuxParams{UDPConn: s})
	err = s.Listen(mux.HandleSTUNMessage)
	require.NoError(t, err, "received an error while listening on STUN packets, error: %s", err)
	defer s.Close()

	buf := make([]byte, 1500)
	err = s.SetReadDeadline(time.Now().Add(3 * time.Second))
	require.NoError(t, err, "unable to set deadline, error: %s", err)

	errGrp := errgroup.Group{}
	errGrp.Go(func() error {
		_, _, err := s.ReadFrom(buf)
		return err
	})
	nonStun := []byte("netbird")
	remote := net.UDPAddrFromAddrPort(netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", testingPort)))
	_, err = udpListener.WriteTo(nonStun, remote)
	require.NoError(t, err, "received an error while writing the stun listener, error: %s", err)

	err = errGrp.Wait()
	require.Error(t, err, "should receive an error")
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("error should be I/O timeout, got: %s", err)
	}
}

func TestWrite(t *testing.T) {
	udpListener, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 0, IP: net.ParseIP("127.0.0.1")})
	require.NoError(t, err, "received an error while creating regular listener, error: %s", err)
	defer udpListener.Close()

	testingPort := 39440
	ctx, cancel := context.WithTimeout(context.TODO(), 10*time.Second)
	defer cancel()
	s, err := NewSTUNListener(ctx, testingPort)
	require.NoError(t, err, "received an error while creating stun listener, error: %s", err)
	mux := bind.NewUniversalUDPMuxDefault(bind.UniversalUDPMuxParams{UDPConn: s})
	err = s.Listen(mux.HandleSTUNMessage)
	require.NoError(t, err, "received an error while listening on STUN packets, error: %s", err)
	defer s.Close()

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
	_, err = s.WriteTo(msg, udpListener.LocalAddr())
	require.NoError(t, err, "received an error while writing the stun listener, error: %s", err)

	err = errGrp.Wait()
	require.NoError(t, err, "received an error while reading the packet, error: %s", err)

	require.EqualValues(t, string(msg), string(buf[:rcvBytes]), "received message should match")

	udpRcv, ok := remoteAdr.(*net.UDPAddr)
	require.True(t, ok, "udp address conversion didn't work")

	require.EqualValues(t, testingPort, udpRcv.Port, "received address port didn't match")
}
