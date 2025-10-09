package loadtest

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

// LoadTestConfig configuration for the load test
type LoadTestConfig struct {
	ServerURL      string
	PairsPerSecond int
	TotalPairs     int
	MessageSize    int
	TestDuration   time.Duration
	RampUpDuration time.Duration
}

// LoadTestMetrics metrics collected during the load test
type LoadTestMetrics struct {
	TotalPairsSent         atomic.Int64
	TotalMessagesExchanged atomic.Int64
	TotalErrors            atomic.Int64
	SuccessfulExchanges    atomic.Int64
	FailedExchanges        atomic.Int64

	mu        sync.Mutex
	latencies []time.Duration
	startTime time.Time
	endTime   time.Time
}

// PeerPair represents a sender-receiver pair
type PeerPair struct {
	sender   *Client
	receiver *Client
	pairID   int
}

// LoadTest manages the load test execution
type LoadTest struct {
	config  LoadTestConfig
	metrics *LoadTestMetrics
	ctx     context.Context
	cancel  context.CancelFunc
}

// NewLoadTest creates a new load test instance
func NewLoadTest(config LoadTestConfig) *LoadTest {
	ctx, cancel := context.WithCancel(context.Background())
	return &LoadTest{
		config:  config,
		metrics: &LoadTestMetrics{},
		ctx:     ctx,
		cancel:  cancel,
	}
}

// Run executes the load test
func (lt *LoadTest) Run() error {
	lt.metrics.startTime = time.Now()
	defer func() {
		lt.metrics.endTime = time.Now()
	}()

	log.Infof("Starting load test: %d pairs/sec, %d total pairs, message size: %d bytes",
		lt.config.PairsPerSecond, lt.config.TotalPairs, lt.config.MessageSize)

	var wg sync.WaitGroup
	pairChan := make(chan int, lt.config.PairsPerSecond)

	for i := 0; i < lt.config.PairsPerSecond; i++ {
		wg.Add(1)
		go lt.pairWorker(&wg, pairChan)
	}

	testCtx := lt.ctx
	if lt.config.TestDuration > 0 {
		var testCancel context.CancelFunc
		testCtx, testCancel = context.WithTimeout(lt.ctx, lt.config.TestDuration)
		defer testCancel()
	}

	ticker := time.NewTicker(time.Second / time.Duration(lt.config.PairsPerSecond))
	defer ticker.Stop()

	pairsCreated := 0
	for pairsCreated < lt.config.TotalPairs {
		select {
		case <-testCtx.Done():
			log.Infof("Test duration reached or context cancelled")
			close(pairChan)
			wg.Wait()
			return testCtx.Err()
		case <-ticker.C:
			select {
			case pairChan <- pairsCreated:
				pairsCreated++
			default:
				log.Warnf("Worker pool saturated, skipping pair creation")
			}
		}
	}

	log.Infof("All %d pairs queued, waiting for completion...", pairsCreated)
	close(pairChan)
	wg.Wait()

	return nil
}

func (lt *LoadTest) pairWorker(wg *sync.WaitGroup, pairChan <-chan int) {
	defer wg.Done()

	for pairID := range pairChan {
		if err := lt.executePairExchange(pairID); err != nil {
			lt.metrics.TotalErrors.Add(1)
			lt.metrics.FailedExchanges.Add(1)
			log.Debugf("Pair %d exchange failed: %v", pairID, err)
		} else {
			lt.metrics.SuccessfulExchanges.Add(1)
		}
		lt.metrics.TotalPairsSent.Add(1)
	}
}

func (lt *LoadTest) executePairExchange(pairID int) error {
	senderID := fmt.Sprintf("sender-%d", pairID)
	receiverID := fmt.Sprintf("receiver-%d", pairID)

	sender, err := NewClient(lt.config.ServerURL, senderID)
	if err != nil {
		return fmt.Errorf("create sender: %w", err)
	}
	defer sender.Close()

	receiver, err := NewClient(lt.config.ServerURL, receiverID)
	if err != nil {
		return fmt.Errorf("create receiver: %w", err)
	}
	defer receiver.Close()

	if err := sender.Connect(); err != nil {
		return fmt.Errorf("sender connect: %w", err)
	}

	if err := receiver.Connect(); err != nil {
		return fmt.Errorf("receiver connect: %w", err)
	}

	time.Sleep(50 * time.Millisecond)

	testMessage := make([]byte, lt.config.MessageSize)
	for i := range testMessage {
		testMessage[i] = byte(i % 256)
	}

	startTime := time.Now()

	if err := sender.SendMessage(receiverID, testMessage); err != nil {
		return fmt.Errorf("send message: %w", err)
	}

	receiveDone := make(chan error, 1)
	go func() {
		msg, err := receiver.ReceiveMessage()
		if err != nil {
			receiveDone <- err
			return
		}
		if len(msg.Body) == 0 {
			receiveDone <- fmt.Errorf("empty message body")
			return
		}
		receiveDone <- nil
	}()

	select {
	case err := <-receiveDone:
		if err != nil {
			return fmt.Errorf("receive message: %w", err)
		}
		latency := time.Since(startTime)
		lt.recordLatency(latency)
		lt.metrics.TotalMessagesExchanged.Add(1)
		return nil
	case <-time.After(5 * time.Second):
		return fmt.Errorf("timeout waiting for message")
	case <-lt.ctx.Done():
		return lt.ctx.Err()
	}
}

func (lt *LoadTest) recordLatency(latency time.Duration) {
	lt.metrics.mu.Lock()
	defer lt.metrics.mu.Unlock()
	lt.metrics.latencies = append(lt.metrics.latencies, latency)
}

// Stop stops the load test
func (lt *LoadTest) Stop() {
	lt.cancel()
}

// GetMetrics returns the collected metrics
func (lt *LoadTest) GetMetrics() *LoadTestMetrics {
	return lt.metrics
}

// PrintReport prints a summary report of the test results
func (m *LoadTestMetrics) PrintReport() {
	duration := m.endTime.Sub(m.startTime)

	fmt.Println("\n=== Load Test Report ===")
	fmt.Printf("Test Duration: %v\n", duration)
	fmt.Printf("Total Pairs Sent: %d\n", m.TotalPairsSent.Load())
	fmt.Printf("Successful Exchanges: %d\n", m.SuccessfulExchanges.Load())
	fmt.Printf("Failed Exchanges: %d\n", m.FailedExchanges.Load())
	fmt.Printf("Total Messages Exchanged: %d\n", m.TotalMessagesExchanged.Load())
	fmt.Printf("Total Errors: %d\n", m.TotalErrors.Load())

	if duration.Seconds() > 0 {
		throughput := float64(m.SuccessfulExchanges.Load()) / duration.Seconds()
		fmt.Printf("Throughput: %.2f pairs/sec\n", throughput)
	}

	m.mu.Lock()
	latencies := m.latencies
	m.mu.Unlock()

	if len(latencies) > 0 {
		var total time.Duration
		min := latencies[0]
		max := latencies[0]

		for _, lat := range latencies {
			total += lat
			if lat < min {
				min = lat
			}
			if lat > max {
				max = lat
			}
		}

		avg := total / time.Duration(len(latencies))
		fmt.Printf("\nLatency Statistics:\n")
		fmt.Printf("  Min: %v\n", min)
		fmt.Printf("  Max: %v\n", max)
		fmt.Printf("  Avg: %v\n", avg)
	}
	fmt.Println("========================")
}
