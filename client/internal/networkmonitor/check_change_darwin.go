//go:build darwin && !ios

package networkmonitor

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"os/exec"
	"syscall"
	"time"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
)

// todo: refactor to not use static functions

func checkChange(ctx context.Context, nexthopv4, nexthopv6 systemops.Nexthop) error {
	fd, err := unix.Socket(syscall.AF_ROUTE, syscall.SOCK_RAW, syscall.AF_UNSPEC)
	if err != nil {
		return fmt.Errorf("open routing socket: %v", err)
	}

	defer func() {
		err := unix.Close(fd)
		if err != nil && !errors.Is(err, unix.EBADF) {
			log.Warnf("Network monitor: failed to close routing socket: %v", err)
		}
	}()

	routeChanged := make(chan struct{})
	go func() {
		routeCheck(ctx, fd, nexthopv4, nexthopv6)
		close(routeChanged)
	}()

	wakeUp := make(chan struct{})
	go func() {
		wakeUpListen(ctx)
		close(wakeUp)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-routeChanged:
		log.Infof("route change detected")
		return nil
	case <-wakeUp:
		log.Infof("wakeup detected")
		return nil
	}
}

func routeCheck(ctx context.Context, fd int, nexthopv4 systemops.Nexthop, nexthopv6 systemops.Nexthop) {
	for {
		if ctx.Err() != nil {
			return
		}

		buf := make([]byte, 2048)
		n, err := unix.Read(fd, buf)
		if err != nil {
			if !errors.Is(err, unix.EBADF) && !errors.Is(err, unix.EINVAL) {
				log.Warnf("Network monitor: failed to read from routing socket: %v", err)
			}
			continue
		}
		if n < unix.SizeofRtMsghdr {
			log.Debugf("Network monitor: read from routing socket returned less than expected: %d bytes", n)
			continue
		}

		msg := (*unix.RtMsghdr)(unsafe.Pointer(&buf[0]))

		if handleRouteMessage(msg, buf[:n], nexthopv4, nexthopv6) {
			return
		}
	}
}

func wakeUpListen(ctx context.Context) {
	log.Infof("start to watch for system wakeups")
	var (
		initialHash uint32
		err         error
	)

	// Keep retrying until initial sysctl succeeds or context is canceled
	for {
		select {
		case <-ctx.Done():
			log.Info("exit from wakeUpListen initial hash detection due to context cancellation")
			return
		default:
			initialHash, err = readSleepTimeHash()
			if err != nil {
				log.Errorf("failed to detect initial sleep time: %v", err)
				select {
				case <-ctx.Done():
					log.Info("exit from wakeUpListen initial hash detection due to context cancellation")
					return
				case <-time.After(3 * time.Second):
					continue
				}
			}
			log.Infof("initial wakeup hash: %d", initialHash)
			break
		}
		break
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info("context canceled, stopping wakeUpListen")
			return

		case <-ticker.C:
			newHash, err := readSleepTimeHash()
			if err != nil {
				log.Errorf("failed to read sleep time hash: %v", err)
				continue
			}

			if newHash == initialHash {
				log.Infof("no wakeup detected")
				continue
			}

			upOut, err := exec.Command("uptime").Output()
			if err != nil {
				log.Errorf("failed to run uptime command: %v", err)
				upOut = []byte("unknown")
			}
			log.Infof("Wakeup detected: %d -> %d, uptime: %s", initialHash, newHash, upOut)
			return
		}
	}
}

func readSleepTimeHash() (uint32, error) {
	cmd := exec.Command("sysctl", "kern.sleeptime")
	out, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("failed to run sysctl: %w", err)
	}

	h, err := hash(out)
	if err != nil {
		return 0, fmt.Errorf("failed to compute hash: %w", err)
	}

	return h, nil
}

func hash(data []byte) (uint32, error) {
	hasher := fnv.New32a() // Create a new 32-bit FNV-1a hasher
	if _, err := hasher.Write(data); err != nil {
		return 0, err
	}
	return hasher.Sum32(), nil
}
