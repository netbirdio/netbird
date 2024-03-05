//go:build !linux

package grpc

import "google.golang.org/grpc"

func NewCustomDialer(fwmark int) grpc.DialOption {
	return grpc.EmptyDialOption{}
}
