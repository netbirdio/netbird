package main

import (
	"crypto/rand"
	"flag"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

var (
	dataSize            = 1024 * 1024 * 10 // 5MB
	pairs               = []int{1, 3, 5, 10, 50, 100}
	relaySrvAddress     = "rel://relay-eu1.stage.npeer.io:80"
	turnSrvAddress      = "relay-eu1.stage.npeer.io:3478"
	signalAddress       = "http://172.20.8.77:8081" // ip address of the receiver instance
	signalListenAddress = ":8081"
)

type testResult struct {
	numOfPairs int
	duration   time.Duration
	speed      float64
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
	mbps := float64(dataSize) / avgDuration.Seconds() / 1024 / 1024
	return avgDuration, mbps
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

		// give time to prepare new receivers
		if n < len(pairs)-1 {
			time.Sleep(3 * time.Second)
		}
	}

}

// TRUNServerMain is the sender
// - allocate turn clients
// - send relayed addresses to signal server in batch
// - wait for signal server to send back addresses in a map
// - send test data to each address in parallel
func TRUNServerMain() {
	log.Infof("starting turn test")

	log.Infof("starting seed random data: %d", dataSize)
	testData, err := seedRandomData(dataSize)
	if err != nil {
		log.Fatalf("failed to seed random data: %s", err)
	}

	ss := SignalClient{signalAddress}

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

		log.Infof("send addresses via signal server: %v", addresses)
		clientAddresses, err := ss.SendAddress(addresses)
		if err != nil {
			log.Fatalf("failed to send address: %s", err)
		}

		wg := sync.WaitGroup{}
		wg.Add(len(clientAddresses.Address))
		for k, v := range clientAddresses.Address {
			go func(k, v string) {
				log.Infof("sending test data to: %s", v)
				defer wg.Done()
				tc, ok := turnConns[k]
				if !ok {
					log.Fatalf("failed to find turn conn: %s", k)
				}
				addr, err := net.ResolveUDPAddr("udp", v)
				if err != nil {
					log.Fatalf("failed to resolve udp address: %s", err)
				}
				tc.WriteTestData(testData, addr)
			}(k, v)
		}
		wg.Wait()
	}
}

func TURNClientMain() []testResult {
	log.Infof("starting turn client test")
	si := NewSignalService()
	go func() {
		log.Infof("starting signal server")
		err := si.Listen(signalListenAddress)
		if err != nil {
			log.Errorf("failed to listen: %s", err)
		}
	}()

	testResults := make([]testResult, 0, len(pairs))
	for _ = range pairs {
		log.Infof("waiting for addresses")
		addresses := <-si.AddressesChan
		log.Infof("received addresses: %d", len(addresses))

		conns := make([]*UDPConn, 0, len(addresses))
		clientAddresses := make(map[string]string, len(addresses))
		for _, addr := range addresses {
			conn, err := Dial(addr)
			if err != nil {
				log.Fatalf("failed to dial: %s", err)
			}
			log.Infof("made client UDP conn: %s", conn.LocalAddr())
			conns = append(conns, conn)
			clientAddresses[addr] = conn.LocalAddr().String()
		}

		// send back local addresses
		log.Infof("response addresses back: %v", clientAddresses)
		si.ClientAddressChan <- clientAddresses

		durations := make(chan time.Duration, len(conns))
		for _, c := range conns {
			go func(c *UDPConn) {
				log.Infof("start to read test data from: %s", c.RemoteAddr())
				duration := c.ReadTestData(c)
				durations <- duration
				_ = c.Close()
			}(c)
		}

		durationsList := make([]time.Duration, 0, len(conns))
		for d := range durations {
			durationsList = append(durationsList, d)
			if len(durationsList) == len(conns) {
				close(durations)
			}
		}

		avgDuration, avgSpeed := avg(durationsList)
		ts := testResult{
			numOfPairs: len(conns),
			duration:   avgDuration,
			speed:      avgSpeed,
		}
		testResults = append(testResults, ts)
	}

	return testResults
}

func main() {
	log.SetLevel(log.DebugLevel)
	var mode string
	flag.StringVar(&mode, "mode", "sender", "sender or receiver mode")
	flag.Parse()

	if mode == "receiver" {
		relayResult := RelayReceiverMain()
		time.Sleep(3 * time.Second)
		turnResults := TURNClientMain()

		for i := 0; i < len(turnResults); i++ {
			log.Infof("pairs: %d, relay duration: %s, relay speed: %.2f MB/s", relayResult[i].numOfPairs, relayResult[i].duration, relayResult[i].speed)
			log.Infof("pairs: %d, turn duration: %s, turn speed: %.2f MB/s", turnResults[i].numOfPairs, turnResults[i].duration, turnResults[i].speed)
		}
	} else {
		RelaySenderMain()
		// grant time for receiver to start
		time.Sleep(6 * time.Second)
		TRUNServerMain()
	}
}
