package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/signal/loadtest"
)

var (
	serverURL          string
	pairsPerSecond     int
	totalPairs         int
	messageSize        int
	testDuration       time.Duration
	exchangeDuration   time.Duration
	messageInterval    time.Duration
	insecureSkipVerify bool
	logLevel           string
)

func init() {
	flag.StringVar(&serverURL, "server", "http://localhost:10000", "Signal server URL (http:// or https://)")
	flag.IntVar(&pairsPerSecond, "pairs-per-sec", 10, "Number of peer pairs to create per second")
	flag.IntVar(&totalPairs, "total-pairs", 100, "Total number of peer pairs to create")
	flag.IntVar(&messageSize, "message-size", 100, "Size of test message in bytes")
	flag.DurationVar(&testDuration, "test-duration", 0, "Maximum test duration (0 = unlimited)")
	flag.DurationVar(&exchangeDuration, "exchange-duration", 0, "Duration for continuous message exchange per pair (0 = single message)")
	flag.DurationVar(&messageInterval, "message-interval", 100*time.Millisecond, "Interval between messages in continuous mode")
	flag.BoolVar(&insecureSkipVerify, "insecure-skip-verify", false, "Skip TLS certificate verification (use with self-signed certificates)")
	flag.StringVar(&logLevel, "log-level", "info", "Log level (trace, debug, info, warn, error)")
}

func main() {
	flag.Parse()

	level, err := log.ParseLevel(logLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid log level: %v\n", err)
		os.Exit(1)
	}
	log.SetLevel(level)

	config := loadtest.LoadTestConfig{
		ServerURL:          serverURL,
		PairsPerSecond:     pairsPerSecond,
		TotalPairs:         totalPairs,
		MessageSize:        messageSize,
		TestDuration:       testDuration,
		ExchangeDuration:   exchangeDuration,
		MessageInterval:    messageInterval,
		InsecureSkipVerify: insecureSkipVerify,
	}

	if err := validateConfig(config); err != nil {
		fmt.Fprintf(os.Stderr, "Configuration error: %v\n", err)
		flag.Usage()
		os.Exit(1)
	}

	log.Infof("Signal Load Test Configuration:")
	log.Infof("  Server URL: %s", config.ServerURL)
	log.Infof("  Pairs per second: %d", config.PairsPerSecond)
	log.Infof("  Total pairs: %d", config.TotalPairs)
	log.Infof("  Message size: %d bytes", config.MessageSize)
	if config.InsecureSkipVerify {
		log.Warnf("  TLS certificate verification: DISABLED (insecure)")
	}
	if config.TestDuration > 0 {
		log.Infof("  Test duration: %v", config.TestDuration)
	}
	if config.ExchangeDuration > 0 {
		log.Infof("  Exchange duration: %v", config.ExchangeDuration)
		log.Infof("  Message interval: %v", config.MessageInterval)
	} else {
		log.Infof("  Mode: Single message exchange")
	}
	fmt.Println()

	lt := loadtest.NewLoadTest(config)
	if err := lt.Run(); err != nil {
		log.Errorf("Load test failed: %v", err)
		os.Exit(1)
	}

	metrics := lt.GetMetrics()
	metrics.PrintReport()
}

func validateConfig(config loadtest.LoadTestConfig) error {
	if config.ServerURL == "" {
		return fmt.Errorf("server URL is required")
	}
	if config.PairsPerSecond <= 0 {
		return fmt.Errorf("pairs-per-sec must be greater than 0")
	}
	if config.TotalPairs <= 0 {
		return fmt.Errorf("total-pairs must be greater than 0")
	}
	if config.MessageSize <= 0 {
		return fmt.Errorf("message-size must be greater than 0")
	}
	if config.MessageInterval <= 0 {
		return fmt.Errorf("message-interval must be greater than 0")
	}
	return nil
}
