package networkmonitor

import (
	"context"

	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
)

func checkChange(ctx context.Context, nexthopv4, nexthopv6 systemops.Nexthop) error {
	// Network changes don't apply to WASM, but this must still block.
	//
	// checkChange's contract is to block until a network change is detected;
	// every other platform implements it as a blocking read (netlink socket,
	// route socket, NotifyIpInterfaceChange). monitor.go's checkChanges calls
	// it from a bare `for {}` whose only other statement is a non-blocking
	// send, so returning nil immediately makes that loop spin with no yield
	// point at all. Under TinyGo's cooperative scheduler the runqueue then
	// never empties, control never returns to the JS event loop, and the
	// browser tab freezes hard enough that DevTools cannot pause or profile it.
	//
	// Block until cancelled. checkChanges treats context.Canceled as a clean
	// shutdown and returns without logging an error.
	<-ctx.Done()
	return ctx.Err()
}
