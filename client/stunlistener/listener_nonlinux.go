//go:build !linux

package stunlistener

import (
	"context"
	"fmt"
	"io"

	"github.com/pion/transport/v2"

	"github.com/netbirdio/netbird/iface/bind"
)

func NewUDPMuxWithStunListener(ctx context.Context, tn transport.Net, port int) (*bind.UniversalUDPMuxDefault, io.Closer, error) {
	return nil, nil, fmt.Errorf("unimplemented")
}
