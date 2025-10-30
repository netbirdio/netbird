//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package networkmonitor

import (
	"fmt"

	"golang.org/x/net/route"

	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
)

// Common route parsing function shared across BSD-like systems.
func parseRouteMessage(buf []byte) (*systemops.Route, error) {
	msgs, err := route.ParseRIB(route.RIBTypeRoute, buf)
	if err != nil {
		return nil, fmt.Errorf("parse RIB: %v", err)
	}

	if len(msgs) != 1 {
		return nil, fmt.Errorf("unexpected RIB message msgs: %v", msgs)
	}

	msg, ok := msgs[0].(*route.RouteMessage)
	if !ok {
		return nil, fmt.Errorf("unexpected RIB message type: %T", msgs[0])
	}

	return systemops.MsgToRoute(msg)
}
