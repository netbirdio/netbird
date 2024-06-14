//go:build !android

package wgproxy

import (
	"context"
)

func NewFactory(ctx context.Context, wgPort int) *Factory {
	f := &Factory{wgPort: wgPort}

	return f
}
