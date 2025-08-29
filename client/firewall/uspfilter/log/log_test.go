package log_test

import (
	"context"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/firewall/uspfilter/log"
)

type discard struct{}

func (d *discard) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func BenchmarkLogger(b *testing.B) {
	simpleMessage := "Connection established"

	srcIP := "192.168.1.1"
	srcPort := uint16(12345)
	dstIP := "10.0.0.1"
	dstPort := uint16(443)
	state := 4 // TCPStateEstablished

	protocol := "TCP"
	direction := "outbound"
	flags := uint16(0x18) // ACK + PSH
	sequence := uint32(123456789)
	acknowledged := uint32(987654321)

	b.Run("SimpleMessage", func(b *testing.B) {
		logger := createTestLogger()
		defer cleanupLogger(logger)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			logger.Trace(simpleMessage)
		}
	})

	b.Run("ConntrackMessage", func(b *testing.B) {
		logger := createTestLogger()
		defer cleanupLogger(logger)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			logger.Trace5("TCP connection %s:%d → %s:%d state %d", srcIP, srcPort, dstIP, dstPort, state)
		}
	})

	b.Run("ComplexMessage", func(b *testing.B) {
		logger := createTestLogger()
		defer cleanupLogger(logger)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			logger.Trace6("Complex trace: proto=%s dir=%s flags=%d seq=%d ack=%d size=%d", protocol, direction, flags, sequence, acknowledged, 1460)
		}
	})
}

// BenchmarkLoggerParallel tests the logger under concurrent load
func BenchmarkLoggerParallel(b *testing.B) {
	logger := createTestLogger()
	defer cleanupLogger(logger)

	srcIP := "192.168.1.1"
	srcPort := uint16(12345)
	dstIP := "10.0.0.1"
	dstPort := uint16(443)
	state := 4

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			logger.Trace5("TCP connection %s:%d → %s:%d state %d", srcIP, srcPort, dstIP, dstPort, state)
		}
	})
}

// BenchmarkLoggerBurst tests how the logger handles bursts of messages
func BenchmarkLoggerBurst(b *testing.B) {
	logger := createTestLogger()
	defer cleanupLogger(logger)

	srcIP := "192.168.1.1"
	srcPort := uint16(12345)
	dstIP := "10.0.0.1"
	dstPort := uint16(443)
	state := 4

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < 100; j++ {
			logger.Trace5("TCP connection %s:%d → %s:%d state %d", srcIP, srcPort, dstIP, dstPort, state)
		}
	}
}

func createTestLogger() *log.Logger {
	logrusLogger := logrus.New()
	logrusLogger.SetOutput(&discard{})
	logrusLogger.SetLevel(logrus.TraceLevel)
	return log.NewFromLogrus(logrusLogger)
}

func cleanupLogger(logger *log.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_ = logger.Stop(ctx)
}
