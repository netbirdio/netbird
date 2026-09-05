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
// raised because the operation needs root/administrator is already guidance
// written for the user, so it is surfaced on its own instead of buried under the
// gRPC envelope and the name of the RPC that hit it. Anything else is wrapped
// with context as usual.
func daemonCallError(context string, err error) error {
	if guidance, ok := privilegeGuidance(err); ok {
		return errors.New(guidance)
	}
	return fmt.Errorf("%s: %w", context, err)
}

// privilegeGuidance renders the daemon's privilege refusal as a summary and the
// command that performs the operation with the privileges it needs. It reports
// false for any other error.
func privilegeGuidance(err error) (string, bool) {
	info, ok := privilegeErrorInfo(err)
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

// privilegeErrorInfo returns the daemon's privilege-refusal detail, if the error
// carries one.
func privilegeErrorInfo(err error) (*errdetails.ErrorInfo, bool) {
	if err == nil {
		return nil, false
	}

	for _, detail := range gstatus.Convert(err).Details() {
		info, ok := detail.(*errdetails.ErrorInfo)
		if !ok {
			continue
		}
		if info.GetReason() == ipcauth.ErrorReasonPrivilegeRequired && info.GetDomain() == ipcauth.ErrorDomain {
			return info, true
		}
	}
	return nil, false
}
