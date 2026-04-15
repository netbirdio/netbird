package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/util/capture"
)

var captureCmd = &cobra.Command{
	Use:   "capture",
	Short: "Capture packets on the WireGuard interface",
	Long: `Captures decrypted packets flowing through the WireGuard interface.

Default output is human-readable text. Use --pcap or --output for pcap binary.
Requires --enable-capture to be set at service install or reconfigure time.

Examples:
  netbird debug capture
  netbird debug capture host 100.64.0.1 and port 443
  netbird debug capture tcp
  netbird debug capture icmp
  netbird debug capture src host 10.0.0.1 and dst port 80
  netbird debug capture -o capture.pcap
  netbird debug capture --pcap | tshark -r -
  netbird debug capture --pcap | tcpdump -r - -n`,
	Args: cobra.ArbitraryArgs,
	RunE: runCapture,
}

func init() {
	debugCmd.AddCommand(captureCmd)

	captureCmd.Flags().Bool("pcap", false, "Force pcap binary output (default when --output is set)")
	captureCmd.Flags().BoolP("verbose", "v", false, "Show seq/ack, TTL, window, total length")
	captureCmd.Flags().Bool("ascii", false, "Print payload as ASCII after each packet (useful for HTTP)")
	captureCmd.Flags().Uint32("snap-len", 0, "Max bytes per packet (0 = full)")
	captureCmd.Flags().DurationP("duration", "d", 0, "Capture duration (0 = until interrupted)")
	captureCmd.Flags().StringP("output", "o", "", "Write pcap to file instead of stdout")
}

func runCapture(cmd *cobra.Command, args []string) error {
	conn, err := getClient(cmd)
	if err != nil {
		return err
	}
	defer func() {
		if err := conn.Close(); err != nil {
			cmd.PrintErrf(errCloseConnection, err)
		}
	}()

	client := proto.NewDaemonServiceClient(conn)

	req, err := buildCaptureRequest(cmd, args)
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	stream, err := client.StartCapture(ctx, req)
	if err != nil {
		return handleCaptureError(err)
	}

	// First Recv is the empty acceptance message from the server. If the
	// device is unavailable (kernel WG, not connected, capture disabled),
	// the server returns an error instead.
	if _, err := stream.Recv(); err != nil {
		return handleCaptureError(err)
	}

	out, cleanup, err := captureOutput(cmd)
	if err != nil {
		return err
	}
	defer cleanup()

	if req.TextOutput {
		cmd.PrintErrf("Capturing packets... Press Ctrl+C to stop.\n")
	} else {
		cmd.PrintErrf("Capturing packets (pcap)... Press Ctrl+C to stop.\n")
	}

	return streamCapture(ctx, cmd, stream, out)
}

func buildCaptureRequest(cmd *cobra.Command, args []string) (*proto.StartCaptureRequest, error) {
	req := &proto.StartCaptureRequest{}

	if len(args) > 0 {
		expr := strings.Join(args, " ")
		if _, err := capture.ParseFilter(expr); err != nil {
			return nil, fmt.Errorf("invalid filter: %w", err)
		}
		req.FilterExpr = expr
	}

	if snap, _ := cmd.Flags().GetUint32("snap-len"); snap > 0 {
		req.SnapLen = snap
	}
	if d, _ := cmd.Flags().GetDuration("duration"); d != 0 {
		if d < 0 {
			return nil, fmt.Errorf("duration must not be negative")
		}
		req.Duration = durationpb.New(d)
	}
	req.Verbose, _ = cmd.Flags().GetBool("verbose")
	req.Ascii, _ = cmd.Flags().GetBool("ascii")

	outPath, _ := cmd.Flags().GetString("output")
	forcePcap, _ := cmd.Flags().GetBool("pcap")
	req.TextOutput = !forcePcap && outPath == ""

	return req, nil
}

func streamCapture(ctx context.Context, cmd *cobra.Command, stream proto.DaemonService_StartCaptureClient, out io.Writer) error {
	for {
		pkt, err := stream.Recv()
		if err != nil {
			if ctx.Err() != nil {
				cmd.PrintErrf("\nCapture stopped.\n")
				return nil //nolint:nilerr // user interrupted
			}
			if err == io.EOF {
				cmd.PrintErrf("\nCapture finished.\n")
				return nil
			}
			return handleCaptureError(err)
		}
		if _, err := out.Write(pkt.GetData()); err != nil {
			return fmt.Errorf("write output: %w", err)
		}
	}
}

// captureOutput returns the writer for capture data and a cleanup function.
func captureOutput(cmd *cobra.Command) (io.Writer, func(), error) {
	outPath, _ := cmd.Flags().GetString("output")
	if outPath == "" {
		return os.Stdout, func() {
			// no cleanup needed for stdout
		}, nil
	}

	f, err := os.CreateTemp(filepath.Dir(outPath), filepath.Base(outPath)+".*.tmp")
	if err != nil {
		return nil, nil, fmt.Errorf("create output file: %w", err)
	}
	tmpPath := f.Name()
	return f, func() {
		if err := f.Close(); err != nil {
			cmd.PrintErrf("close output file: %v\n", err)
		}
		if fi, err := os.Stat(tmpPath); err == nil && fi.Size() > 0 {
			if err := os.Rename(tmpPath, outPath); err != nil {
				cmd.PrintErrf("rename output file: %v\n", err)
			} else {
				cmd.PrintErrf("Wrote %s\n", outPath)
			}
		} else {
			os.Remove(tmpPath)
		}
	}, nil
}

func handleCaptureError(err error) error {
	if s, ok := status.FromError(err); ok {
		return fmt.Errorf("%s", s.Message())
	}
	return err
}
