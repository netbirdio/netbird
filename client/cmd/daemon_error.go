package cmd

import (
	"context"
	"errors"
	"fmt"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
)

// errDaemonAccessDenied reports that the daemon socket refuses this user.
var errDaemonAccessDenied = errors.New("this account is not allowed to use the NetBird daemon on this device: " +
	"an administrator restricted it to other users or groups")

// daemonConnectError explains a failed dial.
func daemonConnectError(err error) error {
	if errors.Is(err, errDaemonAccessDenied) {
		return err
	}
	//nolint
	return fmt.Errorf("failed to connect to daemon error: %v\n"+
		"If the daemon is not running please run: "+
		"\nnetbird service install \nnetbird service start\n", err)
}

// daemonCallError adds the context a failed daemon call happened in.
func daemonCallError(context string, err error) error {
	return fmt.Errorf("%s: %w", context, err)
}

// denialGuidance renders a refusal the daemon explained: a summary, plus the
// command that satisfies it when there is one. A refusal the caller cannot act
// on, such as another user holding the connection, carries a summary alone. It
// reports false for any other error.
func denialGuidance(err error) (string, bool) {
	denial, ok := ipcauth.DenialFrom(err)
	if !ok {
		return "", false
	}
	if denial.Command == "" {
		return denial.Summary, true
	}
	return fmt.Sprintf("%s\n\n    %s\n", denial.Summary, denial.Command), true
}

// daemonDenial is a refusal the daemon explained, carrying its own sentence as
// the error text while keeping the gRPC status underneath.
type daemonDenial struct {
	status  *gstatus.Status
	summary string
}

func (d daemonDenial) Error() string               { return d.summary }
func (d daemonDenial) GRPCStatus() *gstatus.Status { return d.status }

// asDaemonDenial re-presents a refusal the daemon explained. Anything else is
// returned untouched.
func asDaemonDenial(err error) error {
	guidance, ok := denialGuidance(err)
	if !ok {
		return err
	}
	return daemonDenial{status: gstatus.Convert(err), summary: guidance}
}

// denialInterceptor re-presents refusals as they leave the daemon, before any
// command gets a chance to wrap them.
func denialInterceptor(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	return asDaemonDenial(invoker(ctx, method, req, reply, cc, opts...))
}

// denialStreamInterceptor does the same for a stream, on the way out and for as
// long as it runs.
func denialStreamInterceptor(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	stream, err := streamer(ctx, desc, cc, method, opts...)
	if err != nil {
		return stream, asDaemonDenial(err)
	}
	return denialStream{ClientStream: stream}, nil
}

// denialStream re-presents refusals a stream reports after it was opened.
type denialStream struct {
	grpc.ClientStream
}

func (s denialStream) RecvMsg(m any) error {
	return asDaemonDenial(s.ClientStream.RecvMsg(m))
}

func (s denialStream) SendMsg(m any) error {
	return asDaemonDenial(s.ClientStream.SendMsg(m))
}

func (s denialStream) Header() (metadata.MD, error) {
	md, err := s.ClientStream.Header()
	return md, asDaemonDenial(err)
}

// printCommandError writes a failed command's error, taking over from cobra so a
// refusal the daemon explained is printed as written.
func printCommandError(cmd *cobra.Command, err error) {
	// Keep the raw error at debug
	log.Debugf("command failed: %v", err)

	// Unwrapped, so a command that added context with %w still prints the
	// sentence alone. A command that used %v keeps its prefix, and the sentence
	// is still readable because daemonDenial carries no envelope.
	var denial daemonDenial
	if errors.As(err, &denial) {
		cmd.PrintErrln(denial.summary)
		return
	}

	// A refusal that reached here as a plain status did not come through the
	// dial helper's interceptor. Render it anyway rather than leaking an
	// envelope because of where it was dialled.
	if guidance, ok := denialGuidance(err); ok {
		cmd.PrintErrln(guidance)
		return
	}

	cmd.PrintErrln(cmd.ErrPrefix(), err.Error())
}
