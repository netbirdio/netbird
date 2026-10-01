//go:build linux || darwin

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
	udpListener     string // used for TURN test
)

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
		turnSender := &TurnSender{}

		createTurnConns(p, turnSender)

		log.Infof("send addresses via signal server: %d", len(turnSender.addresses))
		clientAddresses, err := ss.SendAddress(turnSender.addresses)
		if err != nil {
			log.Fatalf("failed to send address: %s", err)
		}
		log.Infof("received addresses: %v", clientAddresses.Address)

		createSenderDevices(turnSender, clientAddresses)

		log.Infof("waiting for tcpListeners to be ready")
		time.Sleep(2 * time.Second)

		tcpConns := make([]net.Conn, 0, len(turnSender.devices))
		for i := range turnSender.devices {
			addr := fmt.Sprintf("10.0.%d.2:9999", i)
			log.Infof("dialing: %s", addr)
			tcpConn, err := net.Dial("tcp", addr)
			if err != nil {
				log.Fatalf("failed to dial tcp: %s", err)
			}
			tcpConns = append(tcpConns, tcpConn)
		}

		log.Infof("start test data transfer for %d pairs", p)
		testDataLen := len(testData)
		wg := sync.WaitGroup{}
		wg.Add(len(tcpConns))
		for i, tcpConn := range tcpConns {
			log.Infof("sending test data to device: %d", i)
			go runTurnWriting(tcpConn, testData, testDataLen, &wg)
		}
		wg.Wait()

		for _, d := range turnSender.devices {
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

func main() {
	var mode string

	_ = util.InitLog("debug", util.LogConsole)
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
