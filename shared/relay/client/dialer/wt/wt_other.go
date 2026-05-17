//go:build !js

// Package wt's WebTransport dialer is browser-only. This stub keeps the
// package importable from non-WASM builds (for tooling, `go vet`, etc.) without
// pulling in syscall/js. The Dialer here returns an error if used.
package wt

import (
	"context"
	"errors"
	"net"
)

const Network = "wt"

type Dialer struct{}

func (Dialer) Protocol() string { return Network }

func (Dialer) Dial(_ context.Context, _, _ string) (net.Conn, error) {
	return nil, errors.New("WebTransport dialer is only available in WASM builds")
}
