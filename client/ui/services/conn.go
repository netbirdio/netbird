//go:build !android && !ios && !freebsd && !js

package services

import "github.com/netbirdio/netbird/client/proto"

// DaemonConn returns a lazy gRPC client to the NetBird daemon.
// All services receive a DaemonConn so they share a single connection.
type DaemonConn interface {
	Client() (proto.DaemonServiceClient, error)
}

func ptrStr(s string) *string { return &s }
