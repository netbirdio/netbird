//go:build linux && !android

package watcher

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/godbus/dbus/v5"
	log "github.com/sirupsen/logrus"
)

const (
	systemdNetworkdDest         = "org.freedesktop.network1"
	systemdNetworkdPath         = "/org/freedesktop/network1"
	systemdNetworkdManagerIface = "org.freedesktop.network1.Manager"
	systemdNetworkdLinkIface    = "org.freedesktop.network1.Link"
)

type systemdNetworkdWatcher struct {
	netbirdIface string

	mu          sync.Mutex
	conn        *dbus.Conn
	cancel      context.CancelFunc
	done        chan struct{}
	linkMatcher func(path dbus.ObjectPath) bool
}

func newSystemdNetworkdWatcher(netbirdIface string) *systemdNetworkdWatcher {
	return &systemdNetworkdWatcher{
		netbirdIface: netbirdIface,
		done:         make(chan struct{}),
	}
}

// Start begins listening to systemd-networkd signals on the system D-Bus.
func (w *systemdNetworkdWatcher) Start(ctx context.Context, handler Handler) error {
	w.mu.Lock()
	if w.conn != nil {
		w.mu.Unlock()
		return errors.New("systemd-networkd watcher already started")
	}

	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		w.mu.Unlock()
		return fmt.Errorf("connect to system bus: %w", err)
	}

	ctx, cancel := context.WithCancel(ctx)
	w.conn = conn
	w.cancel = cancel
	w.mu.Unlock()

	defer close(w.done)

	if err := conn.AddMatchSignal(
		dbus.WithMatchSender(systemdNetworkdDest),
		dbus.WithMatchInterface(dbusPropertiesIface),
		dbus.WithMatchMember("PropertiesChanged"),
	); err != nil {
		log.Warnf("failed to add dbus match signal for systemd-networkd: %v", err)
	}

	signalChan := make(chan *dbus.Signal, 64)
	conn.Signal(signalChan)
	defer conn.RemoveSignal(signalChan)

	for {
		select {
		case <-ctx.Done():
			w.mu.Lock()
			if closeErr := conn.Close(); closeErr != nil {
				log.Debugf("close dbus connection: %v", closeErr)
			}
			w.conn = nil
			w.mu.Unlock()
			return ctx.Err()

		case sig, ok := <-signalChan:
			if !ok {
				return nil
			}
			w.handleSignal(sig, handler)
		}
	}
}

// Stop terminates the watcher and releases its D-Bus subscription.
func (w *systemdNetworkdWatcher) Stop() error {
	w.mu.Lock()
	cancel := w.cancel
	w.mu.Unlock()

	if cancel != nil {
		cancel()
		<-w.done
	}
	return nil
}

func parseOperationalState(state string) (EventKind, string, bool) {
	switch state {
	case "off", "dormant", "no-carrier":
		return EventNetworkDisconnected, fmt.Sprintf("systemd-networkd state: %s", state), true
	case "routable", "degraded", "carrier":
		return EventNetworkConnected, fmt.Sprintf("systemd-networkd state: %s", state), true
	default:
		return 0, "", false
	}
}

func (w *systemdNetworkdWatcher) isNetBirdLink(path dbus.ObjectPath) bool {
	if w.linkMatcher != nil {
		return w.linkMatcher(path)
	}
	if w.netbirdIface == "" {
		return false
	}
	iface, err := net.InterfaceByName(w.netbirdIface)
	if err != nil {
		return false
	}
	expected := dbus.ObjectPath(fmt.Sprintf("%s/link/_%d", systemdNetworkdPath, iface.Index))
	return path == expected
}

func (w *systemdNetworkdWatcher) handleSignal(sig *dbus.Signal, handler Handler) {
	if sig == nil || len(sig.Body) < 2 {
		return
	}
	iface, ok := sig.Body[0].(string)
	if !ok {
		return
	}
	changed, ok := sig.Body[1].(map[string]dbus.Variant)
	if !ok {
		return
	}

	switch iface {
	case systemdNetworkdManagerIface:
		if v, exists := changed["OperationalState"]; exists {
			if state, ok := v.Value().(string); ok {
				if kind, reason, match := parseOperationalState(state); match {
					handler.OnNetworkEvent(Event{
						Kind:   kind,
						Reason: reason,
					})
				}
			}
		}

	case systemdNetworkdLinkIface:
		if !w.isNetBirdLink(sig.Path) {
			return
		}
		if v, exists := changed["AdministrativeState"]; exists {
			if state, ok := v.Value().(string); ok && state == "down" {
				handler.OnNetworkEvent(Event{
					Kind:   EventNetBirdInterfaceDisconnected,
					Name:   w.netbirdIface,
					Reason: "systemd-networkd administrative state down",
				})
				return
			}
		}
		if v, exists := changed["OperationalState"]; exists {
			if state, ok := v.Value().(string); ok && (state == "off" || state == "no-carrier" || state == "dormant") {
				handler.OnNetworkEvent(Event{
					Kind:   EventNetBirdInterfaceDisconnected,
					Name:   w.netbirdIface,
					Reason: fmt.Sprintf("systemd-networkd link operational state %s", state),
				})
			}
		}
	}
}
