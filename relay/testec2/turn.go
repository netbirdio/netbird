//go:build linux || darwin

package main

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/netbirdio/netbird/relay/testec2/tun"

	log "github.com/sirupsen/logrus"
)

type TurnReceiver struct {
	conns           []*net.UDPConn
	clientAddresses map[string]string
	devices         []*tun.Device
}

type TurnSender struct {
	turnConns map[string]*TurnConn
	addresses []string
	devices   []*tun.Device
}

func runTurnWriting(tcpConn net.Conn, testData []byte, testDataLen int, wg *sync.WaitGroup) {
	defer wg.Done()
	defer tcpConn.Close()

	log.Infof("start to sending test data: %s", tcpConn.RemoteAddr())

	si := NewStartInidication(time.Now(), testDataLen)
	_, err := tcpConn.Write(si)
	if err != nil {
		log.Errorf("failed to write to tcp: %s", err)
		return
	}

	pieceSize := 1024
	for j := 0; j < testDataLen; j += pieceSize {
		end := j + pieceSize
		if end > testDataLen {
			end = testDataLen
		}
		_, writeErr := tcpConn.Write(testData[j:end])
		if writeErr != nil {
			log.Errorf("failed to write to tcp conn: %s", writeErr)
			return
		}
	}

	// grant time to flush out packages
	time.Sleep(3 * time.Second)
}

func createSenderDevices(sender *TurnSender, clientAddresses *ClientPeerAddr) {
	var i int
	devices := make([]*tun.Device, 0, len(clientAddresses.Address))
	for k, v := range clientAddresses.Address {
		tc, ok := sender.turnConns[k]
		if !ok {
			log.Fatalf("failed to find turn conn: %s", k)
		}

		addr, err := net.ResolveUDPAddr("udp", v)
		if err != nil {
			log.Fatalf("failed to resolve udp address: %s", err)
		}
		device := &tun.Device{
			Name:    fmt.Sprintf("mtun-sender-%d", i),
			IP:      fmt.Sprintf("10.0.%d.1", i),
			PConn:   tc.relayConn,
			DstAddr: addr,
		}

		err = device.Up()
		if err != nil {
			log.Fatalf("failed to bring up device: %s", err)
		}

		devices = append(devices, device)
		i++
	}
	sender.devices = devices
}

func createTurnConns(p int, sender *TurnSender) {
	turnConns := make(map[string]*TurnConn)
	addresses := make([]string, 0, len(pairs))
	for i := 0; i < p; i++ {
		tc := AllocateTurnClient(turnSrvAddress)
		log.Infof("allocated turn client: %s", tc.Address().String())
		turnConns[tc.Address().String()] = tc
		addresses = append(addresses, tc.Address().String())
	}

	sender.turnConns = turnConns
	sender.addresses = addresses
}

func runTurnReading(d *tun.Device, durations chan time.Duration) {
	tcpListener, err := net.Listen("tcp", d.IP+":9999")
	if err != nil {
		log.Fatalf("failed to listen on tcp: %s", err)
	}
	log := log.WithField("device", tcpListener.Addr())

	tcpConn, err := tcpListener.Accept()
	if err != nil {
		_ = tcpListener.Close()
		log.Fatalf("failed to accept connection: %s", err)
	}
	log.Infof("remote peer connected")

	buf := make([]byte, 103)
	n, err := tcpConn.Read(buf)
	if err != nil {
		_ = tcpListener.Close()
		log.Fatalf(errMsgFailedReadTCP, err)
	}

	si := DecodeStartIndication(buf[:n])
	log.Infof("received start indication: %v, %d", si, n)

	buf = make([]byte, 8192)
	i, err := tcpConn.Read(buf)
	if err != nil {
		_ = tcpListener.Close()
		log.Fatalf(errMsgFailedReadTCP, err)
	}
	now := time.Now()
	for i < si.TransferSize {
		n, err := tcpConn.Read(buf)
		if err != nil {
			_ = tcpListener.Close()
			log.Fatalf(errMsgFailedReadTCP, err)
		}
		i += n
	}
	durations <- time.Since(now)
}

func createDevices(addresses []string, receiver *TurnReceiver) error {
	receiver.conns = make([]*net.UDPConn, 0, len(addresses))
	receiver.clientAddresses = make(map[string]string, len(addresses))
	receiver.devices = make([]*tun.Device, 0, len(addresses))
	for i, addr := range addresses {
		localAddr, err := net.ResolveUDPAddr("udp", udpListener)
		if err != nil {
			return fmt.Errorf("failed to resolve UDP address: %s", err)
		}

		conn, err := net.ListenUDP("udp", localAddr)
		if err != nil {
			return fmt.Errorf("failed to create UDP connection: %s", err)
		}

		receiver.conns = append(receiver.conns, conn)
		receiver.clientAddresses[addr] = conn.LocalAddr().String()

		dstAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return fmt.Errorf("failed to resolve address: %s", err)
		}

		device := &tun.Device{
			Name:    fmt.Sprintf("mtun-%d", i),
			IP:      fmt.Sprintf("10.0.%d.2", i),
			PConn:   conn,
			DstAddr: dstAddr,
		}

		if err = device.Up(); err != nil {
			return fmt.Errorf("failed to bring up device: %s, %s", device.Name, err)
		}
		receiver.devices = append(receiver.devices, device)
	}
	return nil
}
