//go:build linux && !android

package watcher

import (
	"context"
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
	if isNetworkManagerAvailable() {
		log.Infof("using NetworkManager watcher for network events on %s", netbirdIface)
		return newNetworkManagerWatcher(netbirdIface)
	}
	if isSystemdNetworkdAvailable() {
		log.Infof("using systemd-networkd watcher for network events on %s", netbirdIface)
		return newSystemdNetworkdWatcher(netbirdIface)
	}
	log.Infof("using netlink watcher for network events on %s", netbirdIface)
	return newNetlinkWatcher(netbirdIface)
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
