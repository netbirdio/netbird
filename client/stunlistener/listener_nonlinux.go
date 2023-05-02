//go:build !linux

package stunlistener

import (
	"context"
	"fmt"
	"runtime"
)

// NewSTUNListener is not implemented for non linux OS
func NewSTUNListener(ctx context.Context, port int) (STUNListener, error) {
	return nil, fmt.Errorf(fmt.Sprintf("Not supported OS %s. STUNListener is only supported on Linux", runtime.GOOS))
}
