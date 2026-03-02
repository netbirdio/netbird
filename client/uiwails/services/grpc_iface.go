//go:build !(linux && 386)

package services

import (
	"time"

	"github.com/netbirdio/netbird/client/proto"
)

// GRPCClientIface is the interface services use to obtain a daemon client.
type GRPCClientIface interface {
	GetClient(timeout time.Duration) (proto.DaemonServiceClient, error)
}
