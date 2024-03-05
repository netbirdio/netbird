//go:build !linux

package grpc

import "google.golang.org/grpc"

func NewCustomDialer() grpc.DialOption {
	return grpc.EmptyDialOption{}
}
