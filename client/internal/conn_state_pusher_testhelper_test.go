package internal

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// grpcCodes_unimplementedError returns a synthetic gRPC status error
// with codes.Unimplemented. Test-only helper kept in the package so
// the test file doesn't have to import grpc/codes directly.
func grpcCodes_unimplementedError() error {
	return status.Error(codes.Unimplemented, "method SyncPeerConnections not implemented")
}
