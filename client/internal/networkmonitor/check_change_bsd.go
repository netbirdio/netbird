//go:build dragonfly || freebsd || netbsd || openbsd

package networkmonitor

import (
	"context"
	"errors"
	"fmt"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
)

func checkChange(ctx context.Context, nexthopv4, nexthopv6 systemops.Nexthop) error {
	fd, err := prepareFd()
	if err != nil {
		return fmt.Errorf("open routing socket: %v", err)
	}

	defer func() {
		err := unix.Close(fd)
		if err != nil && !errors.Is(err, unix.EBADF) {
			log.Warnf("Network monitor: failed to close routing socket: %v", err)
		}
	}()

	return routeCheck(ctx, fd, nexthopv4, nexthopv6)
}
