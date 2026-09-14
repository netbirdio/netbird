package cmd

import (
	"errors"
	"fmt"
	"strings"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	gstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
)

// daemonCallError prepares a daemon error for display. A refusal the daemon
// explained is already written for the user, so it is surfaced on its own
// instead of buried under the gRPC envelope and the name of the RPC that hit it.
// Anything else is wrapped with context as usual.
func daemonCallError(context string, err error) error {
	if guidance, ok := denialGuidance(err); ok {
		return errors.New(guidance)
	}
	return fmt.Errorf("%s: %w", context, err)
}

// denialGuidance renders a refusal the daemon explained: a summary, plus the
// command that satisfies it when there is one. A refusal the caller cannot act
// on, such as another user holding the connection, carries a summary alone. It
// reports false for any other error.
func denialGuidance(err error) (string, bool) {
	info, ok := denialErrorInfo(err)
	if !ok {
		return "", false
	}

	summary := info.GetMetadata()[ipcauth.ErrorMetaSummary]
	command := info.GetMetadata()[ipcauth.ErrorMetaCommand]
	if summary == "" {
		// Detail without a summary: fall back to the status message, which
		// carries the same text.
		summary = strings.TrimSpace(gstatus.Convert(err).Message())
	}
	if command == "" {
		return summary, true
	}

	return fmt.Sprintf("%s\n\n    %s\n", summary, command), true
}

// denialErrorInfo returns the daemon's refusal detail, if the error carries one.
// Matched on the domain rather than on a list of reasons, so a reason added
// later is rendered rather than silently dropped back to the gRPC envelope.
func denialErrorInfo(err error) (*errdetails.ErrorInfo, bool) {
	if err == nil {
		return nil, false
	}

	for _, detail := range gstatus.Convert(err).Details() {
		info, ok := detail.(*errdetails.ErrorInfo)
		if !ok {
			continue
		}
		if info.GetDomain() == ipcauth.ErrorDomain {
			return info, true
		}
	}
	return nil, false
}
