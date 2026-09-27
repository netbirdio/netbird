//go:build linux && !android

package watcher

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	log "github.com/sirupsen/logrus"
)

// ProviderType identifies the underlying detection backend.
type ProviderType string

const (
	// ProviderNetworkManager indicates NetworkManager D-Bus backend.
	ProviderNetworkManager ProviderType = "NetworkManager"
	// ProviderSystemdNetworkd indicates systemd-networkd D-Bus backend.
	ProviderSystemdNetworkd ProviderType = "systemd-networkd"
	// ProviderNetlink indicates direct netlink backend.
	ProviderNetlink ProviderType = "netlink"
)

// New creates a new network watcher suited for the current Linux environment.
func New(netbirdIface string) Watcher {
	nl := newNetlinkWatcher(netbirdIface)
	if isNetworkManagerAvailable() {
		log.Infof("using NetworkManager watcher with netlink fallback for network events on %s", netbirdIface)
		return newCompositeWatcher(newNetworkManagerWatcher(netbirdIface), nl)
	}
	if isSystemdNetworkdAvailable() {
		log.Infof("using systemd-networkd watcher with netlink fallback for network events on %s", netbirdIface)
		return newCompositeWatcher(newSystemdNetworkdWatcher(netbirdIface), nl)
	}
	log.Infof("using netlink watcher for network events on %s", netbirdIface)
	return nl
}

type compositeWatcher struct {
	watchers []Watcher
}

func newCompositeWatcher(watchers ...Watcher) *compositeWatcher {
	return &compositeWatcher{watchers: watchers}
}

// Start begins listening across all composite watchers.
func (c *compositeWatcher) Start(ctx context.Context, handler Handler) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	errCh := make(chan error, len(c.watchers))

	for _, w := range c.watchers {
		wg.Add(1)
		go func(w Watcher) {
			defer wg.Done()
			if err := w.Start(ctx, handler); err != nil && !errors.Is(err, context.Canceled) {
				select {
				case errCh <- err:
				default:
				}
				cancel()
			}
		}(w)
	}

	doneCh := make(chan struct{})
	go func() {
		wg.Wait()
		close(doneCh)
	}()

	select {
	case err := <-errCh:
		cancel()
		<-doneCh
		return err
	case <-ctx.Done():
		<-doneCh
		select {
		case err := <-errCh:
			return err
		default:
			return ctx.Err()
		}
	}
}

// Stop terminates all sub-watchers.
func (c *compositeWatcher) Stop() error {
	var merr error
	for _, w := range c.watchers {
		if err := w.Stop(); err != nil {
			merr = errors.Join(merr, err)
		}
	}
	return merr
}

func isNetworkManagerAvailable() bool {
	return isDbusServiceAvailable("org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager")
}

func isSystemdNetworkdAvailable() bool {
	return isDbusServiceAvailable("org.freedesktop.network1", "/org/freedesktop/network1")
}

func isDbusServiceAvailable(dest string, path dbus.ObjectPath) bool {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return false
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			log.Debugf("close dbus connection: %v", closeErr)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	obj := conn.Object(dest, path)
	if err := obj.CallWithContext(ctx, "org.freedesktop.DBus.Peer.Ping", 0).Store(); err != nil {
		return false
	}
	return true
}
