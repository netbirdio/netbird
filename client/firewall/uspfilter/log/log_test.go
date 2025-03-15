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

	conntrackMessage := "TCP connection %s:%d -> %s:%d state changed to %d"
	srcIP := "192.168.1.1"
	srcPort := uint16(12345)
	dstIP := "10.0.0.1"
	dstPort := uint16(443)
	state := 4 // TCPStateEstablished

	complexMessage := "Packet inspection result: protocol=%s, direction=%s, flags=0x%x, sequence=%d, acknowledged=%d, payload_size=%d, fragmented=%v, connection_id=%s"
	protocol := "TCP"
	direction := "outbound"
	flags := uint16(0x18) // ACK + PSH
	sequence := uint32(123456789)
	acknowledged := uint32(987654321)
	payloadSize := 1460
	fragmented := false
	connID := "f7a12b3e-c456-7890-d123-456789abcdef"

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
			logger.Trace(conntrackMessage, srcIP, srcPort, dstIP, dstPort, state)
		}
	})

	b.Run("ComplexMessage", func(b *testing.B) {
		logger := createTestLogger()
		defer cleanupLogger(logger)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			logger.Trace(complexMessage, protocol, direction, flags, sequence, acknowledged, payloadSize, fragmented, connID)
		}
	})
}

// BenchmarkLoggerParallel tests the logger under concurrent load
func BenchmarkLoggerParallel(b *testing.B) {
	logger := createTestLogger()
	defer cleanupLogger(logger)

	conntrackMessage := "TCP connection %s:%d -> %s:%d state changed to %d"
	srcIP := "192.168.1.1"
	srcPort := uint16(12345)
	dstIP := "10.0.0.1"
	dstPort := uint16(443)
	state := 4

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			logger.Trace(conntrackMessage, srcIP, srcPort, dstIP, dstPort, state)
		}
	})
}

// BenchmarkLoggerBurst tests how the logger handles bursts of messages
func BenchmarkLoggerBurst(b *testing.B) {
	logger := createTestLogger()
	defer cleanupLogger(logger)

	conntrackMessage := "TCP connection %s:%d -> %s:%d state changed to %d"
	srcIP := "192.168.1.1"
	srcPort := uint16(12345)
	dstIP := "10.0.0.1"
	dstPort := uint16(443)
	state := 4

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < 100; j++ {
			logger.Trace(conntrackMessage, srcIP, srcPort, dstIP, dstPort, state)
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
