//go:build !linux || android

package wgproxy

import "context"

func NewFactory(ctx context.Context, wgPort int) *Factory {
	return &Factory{wgPort: wgPort}
}
