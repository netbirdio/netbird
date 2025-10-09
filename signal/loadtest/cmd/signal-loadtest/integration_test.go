package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/shared/signal/proto"
	"github.com/netbirdio/netbird/signal/server"
)

func TestCLI_SingleMessage(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	grpcServer, serverAddr := startTestSignalServer(t, ctx)
	defer grpcServer.Stop()

	cmd := exec.Command("go", "run", "main.go",
		"-server", serverAddr,
		"-pairs-per-sec", "3",
		"-total-pairs", "5",
		"-message-size", "50",
		"-log-level", "warn")

	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "CLI should execute successfully")

	outputStr := string(output)
	require.Contains(t, outputStr, "Load Test Report")
	require.Contains(t, outputStr, "Total Pairs Sent: 5")
	require.Contains(t, outputStr, "Successful Exchanges: 5")
	t.Logf("Output:\n%s", outputStr)
}

func TestCLI_ContinuousExchange(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping continuous exchange CLI test in short mode")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	grpcServer, serverAddr := startTestSignalServer(t, ctx)
	defer grpcServer.Stop()

	cmd := exec.Command("go", "run", "main.go",
		"-server", serverAddr,
		"-pairs-per-sec", "2",
		"-total-pairs", "3",
		"-message-size", "100",
		"-exchange-duration", "3s",
		"-message-interval", "100ms",
		"-log-level", "warn")

	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "CLI should execute successfully")

	outputStr := string(output)
	require.Contains(t, outputStr, "Load Test Report")
	require.Contains(t, outputStr, "Total Pairs Sent: 3")
	require.Contains(t, outputStr, "Successful Exchanges: 3")
	t.Logf("Output:\n%s", outputStr)
}

func TestCLI_InvalidConfig(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{
			name: "negative pairs",
			args: []string{"-pairs-per-sec", "-1"},
		},
		{
			name: "zero total pairs",
			args: []string{"-total-pairs", "0"},
		},
		{
			name: "negative message size",
			args: []string{"-message-size", "-100"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := append([]string{"run", "main.go"}, tt.args...)
			cmd := exec.Command("go", args...)
			output, err := cmd.CombinedOutput()
			require.Error(t, err, "Should fail with invalid config")
			require.Contains(t, string(output), "Configuration error")
		})
	}
}

func startTestSignalServer(t *testing.T, ctx context.Context) (*grpc.Server, string) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	grpcServer := grpc.NewServer()

	signalServer, err := server.NewServer(ctx, otel.Meter("cli-test"))
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

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
