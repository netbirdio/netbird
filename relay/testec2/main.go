package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/relay/testec2/tun"
	"github.com/netbirdio/netbird/util"
)

const (
	errMsgFailedReadTCP = "failed to read from tcp: %s"
)

var (
	dataSize            = 1024 * 1024 * 50 // 50MB
	pairs               = []int{1, 5, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100}
	signalListenAddress = ":8081"

	relaySrvAddress string
	turnSrvAddress  string
	signalURL       string
	udpListener     string
)

type TurnReceiver struct {
	conns           []*net.UDPConn
	clientAddresses map[string]string
	devices         []*tun.Device
}
type testResult struct {
	numOfPairs int
	duration   time.Duration
	speed      float64
}

func (tr testResult) Speed() string {
	speed := tr.speed
	var unit string

	switch {
	case speed < 1024:
		unit = "B/s"
	case speed < 1048576:
		speed /= 1024
		unit = "KB/s"
	case speed < 1073741824:
		speed /= 1048576
		unit = "MB/s"
	default:
		speed /= 1073741824
		unit = "GB/s"
	}

	return fmt.Sprintf("%.2f %s", speed, unit)
}

func seedRandomData(size int) ([]byte, error) {
	token := make([]byte, size)
	_, err := rand.Read(token)
	if err != nil {
		return nil, err
	}
	return token, nil
}

func avg(transferDuration []time.Duration) (time.Duration, float64) {
	var totalDuration time.Duration
	for _, d := range transferDuration {
		totalDuration += d
	}
	avgDuration := totalDuration / time.Duration(len(transferDuration))
	bps := float64(dataSize) / avgDuration.Seconds()
	return avgDuration, bps
}

func RelayReceiverMain() []testResult {
	testResults := make([]testResult, 0, len(pairs))
	for _, p := range pairs {
		tr := testResult{numOfPairs: p}
		td := relayReceive(relaySrvAddress, p)
		tr.duration, tr.speed = avg(td)

		testResults = append(testResults, tr)
	}

	return testResults
}

func RelaySenderMain() {
	log.Infof("starting sender")
	log.Infof("starting seed phase")

	testData, err := seedRandomData(dataSize)
	if err != nil {
		log.Fatalf("failed to seed random data: %s", err)
	}

	log.Infof("data size: %d", len(testData))

	for n, p := range pairs {
		log.Infof("running test with %d pairs", p)
		relayTransfer(relaySrvAddress, testData, p)

		// grant time to prepare new receivers
		if n < len(pairs)-1 {
			time.Sleep(3 * time.Second)
		}
	}

}

// TRUNSenderMain is the sender
// - allocate turn clients
// - send relayed addresses to signal server in batch
// - wait for signal server to send back addresses in a map
// - send test data to each address in parallel
func TRUNSenderMain() {
	log.Infof("starting TURN sender test")

	log.Infof("starting seed random data: %d", dataSize)
	testData, err := seedRandomData(dataSize)
	if err != nil {
		log.Fatalf("failed to seed random data: %s", err)
	}

	ss := SignalClient{signalURL}

	for _, p := range pairs {
		log.Infof("running test with %d pairs", p)

		turnConns := make(map[string]*TurnConn)
		addresses := make([]string, 0, len(pairs))
		for i := 0; i < p; i++ {
			tc := AllocateTurnClient(turnSrvAddress)
			log.Infof("allocated turn client: %s", tc.Address().String())
			turnConns[tc.Address().String()] = tc
			addresses = append(addresses, tc.Address().String())
		}

		log.Infof("send addresses via signal server: %d", len(addresses))
		clientAddresses, err := ss.SendAddress(addresses)
		if err != nil {
			log.Fatalf("failed to send address: %s", err)
		}
		log.Infof("received addresses: %v", clientAddresses.Address)

		var i int
		devices := make([]*tun.Device, 0, len(clientAddresses.Address))
		for k, v := range clientAddresses.Address {
			tc, ok := turnConns[k]
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

		log.Infof("waiting for tcpListeners to be ready")
		time.Sleep(2 * time.Second)

		tcpConns := make([]net.Conn, 0, len(devices))
		for i := range devices {
			addr := fmt.Sprintf("10.0.%d.2:9999", i)
			log.Infof("dialing: %s", addr)
			tcpConn, err := net.Dial("tcp", addr)
			if err != nil {
				log.Fatalf("failed to dial tcp: %s", err)
			}
			tcpConns = append(tcpConns, tcpConn)
		}

		log.Infof("start test data transfer for %d pairs", len(devices))
		testDataLen := len(testData)
		wg := sync.WaitGroup{}
		for i, tcpConn := range tcpConns {
			log.Infof("sending test data to device: %d", i)
			wg.Add(1)
			go func(i int, tcpConn net.Conn) {
				defer wg.Done()
				defer tcpConn.Close()

				log.Infof("start to sending test data: %s", tcpConn.RemoteAddr())

				si := NewStartInidication(time.Now(), testDataLen)
				_, err = tcpConn.Write(si)
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

				time.Sleep(3 * time.Second)
			}(i, tcpConn)
		}
		wg.Wait()

		for _, d := range devices {
			_ = d.Close()
		}

		log.Infof("test finished with %d pairs", p)
	}
}

func TURNReaderMain() []testResult {
	log.Infof("starting TURN receiver test")
	si := NewSignalService()
	go func() {
		log.Infof("starting signal server")
		err := si.Listen(signalListenAddress)
		if err != nil {
			log.Errorf("failed to listen: %s", err)
		}
	}()

	testResults := make([]testResult, 0, len(pairs))
	for range pairs {
		addresses := <-si.AddressesChan
		instanceNumber := len(addresses)
		log.Infof("received addresses: %d", instanceNumber)

		turnReceiver := &TurnReceiver{}
		err := createDevices(addresses, turnReceiver)
		if err != nil {
			log.Fatalf("%s", err)
		}

		// send client addresses back via signal server
		si.ClientAddressChan <- turnReceiver.clientAddresses

		durations := make(chan time.Duration, instanceNumber)
		for _, device := range turnReceiver.devices {
			go runTurnReading(device, durations)
		}

		durationsList := make([]time.Duration, 0, instanceNumber)
		for d := range durations {
			durationsList = append(durationsList, d)
			if len(durationsList) == instanceNumber {
				close(durations)
			}
		}

		avgDuration, avgSpeed := avg(durationsList)
		ts := testResult{
			numOfPairs: len(durationsList),
			duration:   avgDuration,
			speed:      avgSpeed,
		}
		testResults = append(testResults, ts)

		for _, d := range turnReceiver.devices {
			_ = d.Close()
		}
	}
	return testResults
}

func runTurnReading(d *tun.Device, durations chan time.Duration) {
	tcpListener, err := net.Listen("tcp", d.IP+":9999")
	if err != nil {
		log.Fatalf("failed to listen on tcp: %s", err)
	}
	defer tcpListener.Close()
	log := log.WithField("device", tcpListener.Addr())

	tcpConn, err := tcpListener.Accept()
	if err != nil {
		log.Fatalf("failed to accept connection: %s", err)
	}
	log.Infof("remote peer connected")

	buf := make([]byte, 103)
	n, err := tcpConn.Read(buf)
	if err != nil {
		log.Fatalf(errMsgFailedReadTCP, err)
	}

	si := DecodeStartIndication(buf[:n])
	log.Infof("received start indication: %v, %d", si, n)

	buf = make([]byte, 8192)
	i, err := tcpConn.Read(buf)
	if err != nil {
		log.Fatalf(errMsgFailedReadTCP, err)
	}
	now := time.Now()
	for i < si.TransferSize {
		n, err := tcpConn.Read(buf)
		if err != nil {
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

func main() {
	var mode string

	_ = util.InitLog("debug", "console")
	flag.StringVar(&mode, "mode", "sender", "sender or receiver mode")
	flag.Parse()

	relaySrvAddress = os.Getenv("TEST_RELAY_SERVER") // rel://ip:port
	turnSrvAddress = os.Getenv("TEST_TURN_SERVER")   // ip:3478
	signalURL = os.Getenv("TEST_SIGNAL_URL")         // http://receiver_ip:8081
	udpListener = os.Getenv("TEST_UDP_LISTENER")     // IP:0

	if mode == "receiver" {
		relayResult := RelayReceiverMain()
		turnResults := TURNReaderMain()
		for i := 0; i < len(turnResults); i++ {
			log.Infof("pairs: %d,\tRelay speed:\t%s,\trelay duration:\t%s", relayResult[i].numOfPairs, relayResult[i].Speed(), relayResult[i].duration)
			log.Infof("pairs: %d,\tTURN speed:\t%s,\tturn duration:\t%s", turnResults[i].numOfPairs, turnResults[i].Speed(), turnResults[i].duration)
		}
	} else {
		RelaySenderMain()
		// grant time for receiver to start
		time.Sleep(3 * time.Second)
		TRUNSenderMain()
	}
}
