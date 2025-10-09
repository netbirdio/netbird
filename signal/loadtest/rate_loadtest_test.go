package loadtest

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/shared/signal/proto"
	"github.com/netbirdio/netbird/signal/server"
)

func TestLoadTest_10PairsPerSecond(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping load test in short mode")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	grpcServer, serverAddr := startTestSignalServerForLoad(t, ctx)
	defer grpcServer.Stop()

	config := LoadTestConfig{
		ServerURL:      serverAddr,
		PairsPerSecond: 10,
		TotalPairs:     50,
		MessageSize:    100,
		TestDuration:   30 * time.Second,
	}

	loadTest := NewLoadTest(config)
	err := loadTest.Run()
	require.NoError(t, err)

	metrics := loadTest.GetMetrics()
	metrics.PrintReport()

	require.Equal(t, int64(50), metrics.TotalPairsSent.Load(), "Should send all 50 pairs")
	require.Greater(t, metrics.SuccessfulExchanges.Load(), int64(0), "Should have successful exchanges")
	require.Equal(t, metrics.TotalMessagesExchanged.Load(), metrics.SuccessfulExchanges.Load(), "Messages exchanged should match successful exchanges")
}

func TestLoadTest_20PairsPerSecond(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping load test in short mode")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	grpcServer, serverAddr := startTestSignalServerForLoad(t, ctx)
	defer grpcServer.Stop()

	config := LoadTestConfig{
		ServerURL:      serverAddr,
		PairsPerSecond: 20,
		TotalPairs:     100,
		MessageSize:    500,
		TestDuration:   30 * time.Second,
	}

	loadTest := NewLoadTest(config)
	err := loadTest.Run()
	require.NoError(t, err)

	metrics := loadTest.GetMetrics()
	metrics.PrintReport()

	require.Equal(t, int64(100), metrics.TotalPairsSent.Load(), "Should send all 100 pairs")
	require.Greater(t, metrics.SuccessfulExchanges.Load(), int64(0), "Should have successful exchanges")
}

func TestLoadTest_SmallBurst(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	grpcServer, serverAddr := startTestSignalServerForLoad(t, ctx)
	defer grpcServer.Stop()

	config := LoadTestConfig{
		ServerURL:      serverAddr,
		PairsPerSecond: 5,
		TotalPairs:     10,
		MessageSize:    50,
		TestDuration:   10 * time.Second,
	}

	loadTest := NewLoadTest(config)
	err := loadTest.Run()
	require.NoError(t, err)

	metrics := loadTest.GetMetrics()
	metrics.PrintReport()

	require.Equal(t, int64(10), metrics.TotalPairsSent.Load())
	require.Greater(t, metrics.SuccessfulExchanges.Load(), int64(5), "At least 50% success rate")
	require.Less(t, metrics.FailedExchanges.Load(), int64(5), "Less than 50% failure rate")
}

func TestLoadTest_ContinuousExchange_30Seconds(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping continuous exchange test in short mode")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	grpcServer, serverAddr := startTestSignalServerForLoad(t, ctx)
	defer grpcServer.Stop()

	config := LoadTestConfig{
		ServerURL:        serverAddr,
		PairsPerSecond:   5,
		TotalPairs:       10,
		MessageSize:      100,
		ExchangeDuration: 30 * time.Second,
		MessageInterval:  100 * time.Millisecond,
		TestDuration:     2 * time.Minute,
	}

	loadTest := NewLoadTest(config)
	err := loadTest.Run()
	require.NoError(t, err)

	metrics := loadTest.GetMetrics()
	metrics.PrintReport()

	require.Equal(t, int64(10), metrics.TotalPairsSent.Load())
	require.Greater(t, metrics.TotalMessagesExchanged.Load(), int64(2000), "Should exchange many messages over 30 seconds")
}

func TestLoadTest_ContinuousExchange_10Minutes(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping long continuous exchange test in short mode")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	grpcServer, serverAddr := startTestSignalServerForLoad(t, ctx)
	defer grpcServer.Stop()

	config := LoadTestConfig{
		ServerURL:        serverAddr,
		PairsPerSecond:   10,
		TotalPairs:       20,
		MessageSize:      200,
		ExchangeDuration: 10 * time.Minute,
		MessageInterval:  200 * time.Millisecond,
		TestDuration:     15 * time.Minute,
	}

	loadTest := NewLoadTest(config)
	err := loadTest.Run()
	require.NoError(t, err)

	metrics := loadTest.GetMetrics()
	metrics.PrintReport()

	require.Equal(t, int64(20), metrics.TotalPairsSent.Load())
	require.Greater(t, metrics.TotalMessagesExchanged.Load(), int64(50000), "Should exchange many messages over 10 minutes")
}

func TestLoadTest_ContinuousExchange_ShortBurst(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	grpcServer, serverAddr := startTestSignalServerForLoad(t, ctx)
	defer grpcServer.Stop()

	config := LoadTestConfig{
		ServerURL:        serverAddr,
		PairsPerSecond:   3,
		TotalPairs:       5,
		MessageSize:      50,
		ExchangeDuration: 3 * time.Second,
		MessageInterval:  100 * time.Millisecond,
		TestDuration:     10 * time.Second,
	}

	loadTest := NewLoadTest(config)
	err := loadTest.Run()
	require.NoError(t, err)

	metrics := loadTest.GetMetrics()
	metrics.PrintReport()

	require.Equal(t, int64(5), metrics.TotalPairsSent.Load())
	require.Greater(t, metrics.TotalMessagesExchanged.Load(), int64(100), "Should exchange multiple messages in 3 seconds")
	require.Equal(t, int64(5), metrics.SuccessfulExchanges.Load(), "All pairs should complete successfully")
}

func BenchmarkLoadTest_Throughput(b *testing.B) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	grpcServer, serverAddr := startBenchSignalServer(b, ctx)
	defer grpcServer.Stop()

	b.Run("5pairs-per-sec", func(b *testing.B) {
		config := LoadTestConfig{
			ServerURL:      serverAddr,
			PairsPerSecond: 5,
			TotalPairs:     b.N,
			MessageSize:    100,
		}

		loadTest := NewLoadTest(config)
		b.ResetTimer()
		_ = loadTest.Run()
		b.StopTimer()

		metrics := loadTest.GetMetrics()
		b.ReportMetric(float64(metrics.SuccessfulExchanges.Load()), "successful")
		b.ReportMetric(float64(metrics.FailedExchanges.Load()), "failed")
	})
}

func startTestSignalServerForLoad(t *testing.T, ctx context.Context) (*grpc.Server, string) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	grpcServer := grpc.NewServer()

	signalServer, err := server.NewServer(ctx, otel.Meter("test"))
	require.NoError(t, err)

	proto.RegisterSignalExchangeServer(grpcServer, signalServer)

	go func() {
		if err := grpcServer.Serve(listener); err != nil {
			t.Logf("Server stopped: %v", err)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	return grpcServer, fmt.Sprintf("http://%s", listener.Addr().String())
}

func startBenchSignalServer(b *testing.B, ctx context.Context) (*grpc.Server, string) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(b, err)

	grpcServer := grpc.NewServer()

	signalServer, err := server.NewServer(ctx, otel.Meter("bench"))
	require.NoError(b, err)

	proto.RegisterSignalExchangeServer(grpcServer, signalServer)

	go func() {
		if err := grpcServer.Serve(listener); err != nil {
			b.Logf("Server stopped: %v", err)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	return grpcServer, fmt.Sprintf("http://%s", listener.Addr().String())
}
