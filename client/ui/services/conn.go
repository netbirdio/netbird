//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"

	"github.com/netbirdio/netbird/client/proto"
)

// DaemonConn returns a lazy gRPC client to the NetBird daemon.
// All services receive a DaemonConn so they share a single connection.
type DaemonConn interface {
	Client() (proto.DaemonServiceClient, error)
}

// AccessProber is implemented by a DaemonConn that can probe whether the daemon
// socket refuses this user.
type AccessProber interface {
	DeniesCaller(ctx context.Context) bool
}

func ptrStr(s string) *string { return &s }
