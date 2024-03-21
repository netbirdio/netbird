//go:build !linux || android

package grpc

import "google.golang.org/grpc"

func WithCustomDialer() grpc.DialOption {
	return grpc.EmptyDialOption{}
}
