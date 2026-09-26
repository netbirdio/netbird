//go:build linux && !android

package watcher

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	log "github.com/sirupsen/logrus"
)

const (
	nmDest               = "org.freedesktop.NetworkManager"
	nmPath               = "/org/freedesktop/NetworkManager"
	nmInterface          = "org.freedesktop.NetworkManager"
	nmActiveConnIface    = "org.freedesktop.NetworkManager.Connection.Active"
	nmDeviceIface        = "org.freedesktop.NetworkManager.Device"
	dbusPropertiesIface  = "org.freedesktop.DBus.Properties"
	nmSignalStateChanged = "StateChanged"

	// NMActiveConnectionState constants.
	nmActiveStateActivating   uint32 = 1
	nmActiveStateActivated    uint32 = 2
	nmActiveStateDeactivating uint32 = 3
	nmActiveStateDeactivated  uint32 = 4

	// NMActiveConnectionStateReason constants.
	nmActiveReasonUserDisconnected uint32 = 2

	// NMDeviceState constants.
	nmDeviceStateDisconnected uint32 = 30
	nmDeviceStateActivated    uint32 = 100
	nmDeviceStateDeactivating uint32 = 110
	nmDeviceStateFailed       uint32 = 120

	// NMDeviceStateReason constants.
	nmDeviceReasonUserRequested uint32 = 39

	// NMState constants.
	nmStateDisconnected uint32 = 20
	nmStateConnected    uint32 = 50

	// NMConnectivity constants.
	nmConnectivityNone uint32 = 1
)

type activeConnInfo struct {
	id     string
	cType  string
	vpn    bool
	device string
}

type networkManagerWatcher struct {
	netbirdIface string

	mu               sync.Mutex
	conn             *dbus.Conn
	activeConns      map[dbus.ObjectPath]activeConnInfo
	deviceIfaces     map[dbus.ObjectPath]string
	lastDeviceActive bool
	cancel           context.CancelFunc
	done             chan struct{}
}

func newNetworkManagerWatcher(netbirdIface string) *networkManagerWatcher {
	return &networkManagerWatcher{
		netbirdIface: netbirdIface,
		activeConns:  make(map[dbus.ObjectPath]activeConnInfo),
		deviceIfaces: make(map[dbus.ObjectPath]string),
		done:         make(chan struct{}),
	}
}

// Start begins listening to NetworkManager signals on the system D-Bus.
func (w *networkManagerWatcher) Start(ctx context.Context, handler Handler) error {
	w.mu.Lock()
	if w.conn != nil {
		w.mu.Unlock()
		return errors.New("networkmanager watcher already started")
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

	matchOptions := [][]dbus.MatchOption{
		{dbus.WithMatchSender(nmDest), dbus.WithMatchInterface("org.freedesktop.NetworkManager.VPN.Connection"), dbus.WithMatchMember("VpnStateChanged")},
		{dbus.WithMatchSender(nmDest), dbus.WithMatchInterface(nmActiveConnIface), dbus.WithMatchMember(nmSignalStateChanged)},
		{dbus.WithMatchSender(nmDest), dbus.WithMatchInterface(dbusPropertiesIface), dbus.WithMatchMember("PropertiesChanged")},
		{dbus.WithMatchSender(nmDest), dbus.WithMatchObjectPath(nmPath), dbus.WithMatchInterface(nmInterface), dbus.WithMatchMember("DeviceAdded")},
		{dbus.WithMatchSender(nmDest), dbus.WithMatchObjectPath(nmPath), dbus.WithMatchInterface(nmInterface), dbus.WithMatchMember("DeviceRemoved")},
		{dbus.WithMatchSender(nmDest), dbus.WithMatchObjectPath(nmPath), dbus.WithMatchInterface(nmInterface), dbus.WithMatchMember(nmSignalStateChanged)},
		{dbus.WithMatchSender(nmDest), dbus.WithMatchInterface(nmDeviceIface), dbus.WithMatchMember(nmSignalStateChanged)},
	}

	for _, opts := range matchOptions {
		if err := conn.AddMatchSignal(opts...); err != nil {
			log.Warnf("failed to add dbus match signal: %v", err)
		}
	}

	w.refreshActiveConnections(conn, nil)
	w.findNetbirdDevice(conn)

	signalChan := make(chan *dbus.Signal, 64)
	conn.Signal(signalChan)
	defer conn.RemoveSignal(signalChan)

	log.Infof("NetworkManager watcher: listening on system bus")

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

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

		case <-ticker.C:
			w.checkNetbirdDeviceState(conn, handler)

		case sig, ok := <-signalChan:
			if !ok {
				return nil
			}
			w.handleSignal(conn, sig, handler)
		}
	}
}

// Stop terminates the watcher and releases its D-Bus subscription.
func (w *networkManagerWatcher) Stop() error {
	w.mu.Lock()
	cancel := w.cancel
	w.mu.Unlock()

	if cancel != nil {
		cancel()
		<-w.done
	}
	return nil
}

func (w *networkManagerWatcher) refreshActiveConnections(conn *dbus.Conn, handler Handler) {
	obj := conn.Object(nmDest, nmPath)
	v, err := obj.GetProperty(nmInterface + ".ActiveConnections")
	if err != nil {
		log.Debugf("failed to get active connections: %v", err)
		return
	}

	paths, ok := v.Value().([]dbus.ObjectPath)
	if !ok {
		return
	}

	newConns := make(map[dbus.ObjectPath]activeConnInfo, len(paths))
	newPathsSet := make(map[dbus.ObjectPath]struct{}, len(paths))
	for _, p := range paths {
		newPathsSet[p] = struct{}{}
		newConns[p] = w.fetchConnectionInfo(conn, p)
	}

	w.mu.Lock()
	oldConns := w.activeConns
	w.activeConns = newConns
	w.mu.Unlock()

	if handler == nil {
		return
	}

	for oldPath, oldInfo := range oldConns {
		if _, stillActive := newPathsSet[oldPath]; !stillActive {
			isNetBird := (oldInfo.id == w.netbirdIface || oldInfo.device == w.netbirdIface)
			isVPN := (oldInfo.vpn || oldInfo.cType == "vpn" || oldInfo.cType == "wireguard")

			if isNetBird {
				handler.OnNetworkEvent(Event{
					Kind:          EventNetBirdInterfaceDisconnected,
					Name:          oldInfo.id,
					Reason:        "connection removed from active connections",
					UserInitiated: true,
				})
			} else if isVPN {
				handler.OnNetworkEvent(Event{
					Kind:          EventUnderlyingVPNDisconnected,
					Name:          oldInfo.id,
					Reason:        "vpn connection removed from active connections",
					UserInitiated: true,
				})
			}
		}
	}

	for newPath, newInfo := range newConns {
		if _, wasActive := oldConns[newPath]; !wasActive {
			isNetBird := (newInfo.id == w.netbirdIface || newInfo.device == w.netbirdIface)
			isVPN := (newInfo.vpn || newInfo.cType == "vpn" || newInfo.cType == "wireguard")
			if isVPN && !isNetBird {
				handler.OnNetworkEvent(Event{
					Kind:   EventUnderlyingVPNConnected,
					Name:   newInfo.id,
					Reason: "vpn connection activated",
				})
			}
		}
	}
}

func (w *networkManagerWatcher) checkNetbirdDeviceState(conn *dbus.Conn, handler Handler) {
	if conn == nil || w.netbirdIface == "" {
		return
	}
	obj := conn.Object(nmDest, nmPath)
	var devPath dbus.ObjectPath
	err := obj.Call(nmInterface+".GetDeviceByIpIface", 0, w.netbirdIface).Store(&devPath)
	if err != nil || devPath == "/" || devPath == "" {
		w.mu.Lock()
		wasActive := w.lastDeviceActive
		w.lastDeviceActive = false
		w.mu.Unlock()

		if wasActive {
			log.Infof("NetworkManager watcher: NetBird device %s disappeared from NetworkManager", w.netbirdIface)
			handler.OnNetworkEvent(Event{
				Kind:          EventNetBirdInterfaceDisconnected,
				Name:          w.netbirdIface,
				Reason:        "device disappeared from network manager",
				UserInitiated: true,
			})
		}
		return
	}

	w.mu.Lock()
	w.deviceIfaces[devPath] = w.netbirdIface
	wasActive := w.lastDeviceActive
	w.mu.Unlock()

	devObj := conn.Object(nmDest, devPath)
	v, err := devObj.GetProperty(nmDeviceIface + ".State")
	if err != nil {
		return
	}
	state, ok := v.Value().(uint32)
	if !ok {
		return
	}

	if state == nmDeviceStateActivated {
		w.mu.Lock()
		w.lastDeviceActive = true
		w.mu.Unlock()
		return
	}

	if wasActive && (state == nmDeviceStateDisconnected || state == nmDeviceStateDeactivating || state == nmDeviceStateFailed) {
		w.mu.Lock()
		w.lastDeviceActive = false
		w.mu.Unlock()

		log.Infof("NetworkManager watcher: detected NetBird device %s state %d (was active)", w.netbirdIface, state)
		handler.OnNetworkEvent(Event{
			Kind:          EventNetBirdInterfaceDisconnected,
			Name:          w.netbirdIface,
			Reason:        fmt.Sprintf("network manager device state %d", state),
			UserInitiated: true,
		})
	}
}

func (w *networkManagerWatcher) fetchConnectionInfo(conn *dbus.Conn, path dbus.ObjectPath) activeConnInfo {
	if conn == nil {
		return activeConnInfo{}
	}
	obj := conn.Object(nmDest, path)
	var info activeConnInfo

	if v, err := obj.GetProperty(nmActiveConnIface + ".Id"); err == nil {
		info.id, _ = v.Value().(string)
	}
	if v, err := obj.GetProperty(nmActiveConnIface + ".Type"); err == nil {
		info.cType, _ = v.Value().(string)
	}
	if v, err := obj.GetProperty(nmActiveConnIface + ".Vpn"); err == nil {
		info.vpn, _ = v.Value().(bool)
	}
	if v, err := obj.GetProperty(nmActiveConnIface + ".Devices"); err == nil {
		if devices, ok := v.Value().([]dbus.ObjectPath); ok && len(devices) > 0 {
			info.device = w.fetchDeviceInterface(conn, devices[0])
		}
	}
	return info
}

func (w *networkManagerWatcher) findNetbirdDevice(conn *dbus.Conn) {
	if conn == nil || w.netbirdIface == "" {
		return
	}
	obj := conn.Object(nmDest, nmPath)
	var devPath dbus.ObjectPath
	if err := obj.Call(nmInterface+".GetDeviceByIpIface", 0, w.netbirdIface).Store(&devPath); err == nil && devPath != "/" && devPath != "" {
		w.mu.Lock()
		w.deviceIfaces[devPath] = w.netbirdIface
		w.mu.Unlock()
	}
}

func (w *networkManagerWatcher) fetchDeviceInterface(conn *dbus.Conn, path dbus.ObjectPath) string {
	w.mu.Lock()
	if name, ok := w.deviceIfaces[path]; ok {
		w.mu.Unlock()
		return name
	}
	w.mu.Unlock()

	if conn == nil {
		return ""
	}
	obj := conn.Object(nmDest, path)
	if v, err := obj.GetProperty(nmDeviceIface + ".Interface"); err == nil {
		if iface, ok := v.Value().(string); ok {
			w.mu.Lock()
			w.deviceIfaces[path] = iface
			w.mu.Unlock()
			return iface
		}
	}
	return ""
}

func (w *networkManagerWatcher) handleSignal(conn *dbus.Conn, sig *dbus.Signal, handler Handler) {
	if sig == nil {
		return
	}
	log.Infof("NetworkManager watcher: received signal %s on %s", sig.Name, sig.Path)

	switch {
	case sig.Path == nmPath && strings.HasSuffix(sig.Name, "DeviceRemoved"):
		if len(sig.Body) > 0 {
			if devPath, ok := sig.Body[0].(dbus.ObjectPath); ok {
				w.mu.Lock()
				devIface := w.deviceIfaces[devPath]
				delete(w.deviceIfaces, devPath)
				w.mu.Unlock()

				if devIface == w.netbirdIface || devIface == "" {
					w.findNetbirdDevice(conn)
					w.mu.Lock()
					_, stillExists := w.deviceIfaces[devPath]
					w.mu.Unlock()
					if !stillExists {
						handler.OnNetworkEvent(Event{
							Kind:          EventNetBirdInterfaceDisconnected,
							Name:          w.netbirdIface,
							Reason:        "device removed from network manager",
							UserInitiated: true,
						})
					}
				}
			}
		}

	case sig.Path == nmPath && strings.HasSuffix(sig.Name, "DeviceAdded"):
		if len(sig.Body) > 0 {
			if devPath, ok := sig.Body[0].(dbus.ObjectPath); ok {
				w.fetchDeviceInterface(conn, devPath)
			}
		}

	case strings.HasSuffix(sig.Name, "PropertiesChanged"):
		w.handlePropertiesChanged(conn, sig, handler)

	case strings.HasSuffix(sig.Name, "VpnStateChanged"):
		w.handleVpnStateChanged(sig, handler)

	case sig.Path == nmPath && strings.HasSuffix(sig.Name, nmSignalStateChanged):
		w.handleNMStateChanged(sig, handler)

	case strings.HasPrefix(string(sig.Path), "/org/freedesktop/NetworkManager/ActiveConnection/") &&
		strings.HasSuffix(sig.Name, nmSignalStateChanged):
		w.handleActiveConnectionStateChanged(conn, sig, handler)

	case strings.HasPrefix(string(sig.Path), "/org/freedesktop/NetworkManager/Devices/") &&
		strings.HasSuffix(sig.Name, nmSignalStateChanged):
		w.handleDeviceStateChanged(conn, sig, handler)
	}
}

func (w *networkManagerWatcher) handlePropertiesChanged(conn *dbus.Conn, sig *dbus.Signal, handler Handler) {
	if len(sig.Body) < 2 {
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

	switch {
	case sig.Path == nmPath && iface == nmInterface:
		if _, exists := changed["ActiveConnections"]; exists {
			w.refreshActiveConnections(conn, handler)
		}
		if v, exists := changed["Connectivity"]; exists {
			if connectivity, ok := v.Value().(uint32); ok {
				if connectivity == nmConnectivityNone {
					handler.OnNetworkEvent(Event{
						Kind:   EventNetworkDisconnected,
						Reason: "connectivity lost",
					})
				} else if connectivity >= 3 {
					handler.OnNetworkEvent(Event{
						Kind:   EventNetworkConnected,
						Reason: "connectivity restored",
					})
				}
			}
		}

	case strings.HasPrefix(string(sig.Path), "/org/freedesktop/NetworkManager/Devices/"):
		devIface := w.fetchDeviceInterface(conn, sig.Path)
		if devIface == "" {
			w.findNetbirdDevice(conn)
			devIface = w.fetchDeviceInterface(conn, sig.Path)
		}
		if devIface == w.netbirdIface {
			if v, exists := changed["State"]; exists {
				if state, ok := v.Value().(uint32); ok {
					if state == nmDeviceStateDisconnected || state == nmDeviceStateDeactivating || state == nmDeviceStateFailed {
						handler.OnNetworkEvent(Event{
							Kind:          EventNetBirdInterfaceDisconnected,
							Name:          devIface,
							Reason:        fmt.Sprintf("device state property %d", state),
							UserInitiated: true,
						})
					}
				}
			}
			if v, exists := changed["ActiveConnection"]; exists {
				if activeConn, ok := v.Value().(dbus.ObjectPath); ok && (activeConn == "/" || activeConn == "") {
					handler.OnNetworkEvent(Event{
						Kind:          EventNetBirdInterfaceDisconnected,
						Name:          devIface,
						Reason:        "device active connection cleared",
						UserInitiated: true,
					})
				}
			}
		}

	case strings.HasPrefix(string(sig.Path), "/org/freedesktop/NetworkManager/ActiveConnection/"):
		if v, exists := changed["State"]; exists {
			if state, ok := v.Value().(uint32); ok {
				w.mu.Lock()
				info, found := w.activeConns[sig.Path]
				w.mu.Unlock()
				if !found {
					info = w.fetchConnectionInfo(conn, sig.Path)
				}
				isNetBird := (info.id == w.netbirdIface || info.device == w.netbirdIface)
				isVPN := (info.vpn || info.cType == "vpn" || info.cType == "wireguard")

				if state == nmActiveStateDeactivating || state == nmActiveStateDeactivated {
					if isNetBird {
						handler.OnNetworkEvent(Event{
							Kind:          EventNetBirdInterfaceDisconnected,
							Name:          info.id,
							Reason:        fmt.Sprintf("active connection state property %d", state),
							UserInitiated: true,
						})
					} else if isVPN {
						handler.OnNetworkEvent(Event{
							Kind:          EventUnderlyingVPNDisconnected,
							Name:          info.id,
							Reason:        fmt.Sprintf("vpn connection state property %d", state),
							UserInitiated: true,
						})
					}
				}
			}
		}
	}
}

func (w *networkManagerWatcher) handleVpnStateChanged(sig *dbus.Signal, handler Handler) {
	if len(sig.Body) < 2 {
		return
	}
	vpnState, ok1 := sig.Body[0].(uint32)
	reason, _ := sig.Body[1].(uint32)
	if !ok1 {
		return
	}
	if vpnState == 6 || vpnState == 7 {
		w.mu.Lock()
		info := w.activeConns[sig.Path]
		w.mu.Unlock()
		name := info.id
		if name == "" {
			name = "vpn"
		}
		handler.OnNetworkEvent(Event{
			Kind:          EventUnderlyingVPNDisconnected,
			Name:          name,
			Reason:        fmt.Sprintf("vpn state %d reason %d", vpnState, reason),
			UserInitiated: true,
		})
	}
}

func (w *networkManagerWatcher) handleNMStateChanged(sig *dbus.Signal, handler Handler) {
	if len(sig.Body) < 1 {
		return
	}
	state, ok := sig.Body[0].(uint32)
	if !ok {
		return
	}
	if state <= nmStateDisconnected {
		handler.OnNetworkEvent(Event{
			Kind:   EventNetworkDisconnected,
			Reason: fmt.Sprintf("network manager state %d", state),
		})
	} else if state >= nmStateConnected {
		handler.OnNetworkEvent(Event{
			Kind:   EventNetworkConnected,
			Reason: fmt.Sprintf("network manager state %d", state),
		})
	}
}

func (w *networkManagerWatcher) handleActiveConnectionStateChanged(conn *dbus.Conn, sig *dbus.Signal, handler Handler) {
	if len(sig.Body) < 2 {
		return
	}
	state, ok1 := sig.Body[0].(uint32)
	reason, ok2 := sig.Body[1].(uint32)
	if !ok1 || !ok2 {
		return
	}

	w.mu.Lock()
	info, found := w.activeConns[sig.Path]
	w.mu.Unlock()

	if !found {
		info = w.fetchConnectionInfo(conn, sig.Path)
		if info.id != "" {
			w.mu.Lock()
			w.activeConns[sig.Path] = info
			w.mu.Unlock()
		}
	}

	userInitiated := (reason == nmActiveReasonUserDisconnected)
	isNetBird := (info.id == w.netbirdIface || info.device == w.netbirdIface)
	isVPN := (info.vpn || info.cType == "vpn" || info.cType == "wireguard")

	switch state {
	case nmActiveStateDeactivating, nmActiveStateDeactivated:
		if isNetBird {
			handler.OnNetworkEvent(Event{
				Kind:          EventNetBirdInterfaceDisconnected,
				Name:          info.id,
				Reason:        fmt.Sprintf("active connection state %d reason %d", state, reason),
				UserInitiated: userInitiated,
			})
		} else if isVPN {
			handler.OnNetworkEvent(Event{
				Kind:          EventUnderlyingVPNDisconnected,
				Name:          info.id,
				Reason:        fmt.Sprintf("vpn connection state %d reason %d", state, reason),
				UserInitiated: userInitiated,
			})
		}
		if state == nmActiveStateDeactivated {
			w.mu.Lock()
			delete(w.activeConns, sig.Path)
			w.mu.Unlock()
		}

	case nmActiveStateActivated:
		if isVPN && !isNetBird {
			handler.OnNetworkEvent(Event{
				Kind:   EventUnderlyingVPNConnected,
				Name:   info.id,
				Reason: "vpn connection activated",
			})
		}
	}
}

func (w *networkManagerWatcher) handleDeviceStateChanged(conn *dbus.Conn, sig *dbus.Signal, handler Handler) {
	if len(sig.Body) < 3 {
		return
	}
	newState, ok1 := sig.Body[0].(uint32)
	oldState, _ := sig.Body[1].(uint32)
	reason, ok3 := sig.Body[2].(uint32)
	if !ok1 || !ok3 {
		return
	}

	devIface := w.fetchDeviceInterface(conn, sig.Path)
	if devIface == "" {
		w.findNetbirdDevice(conn)
		devIface = w.fetchDeviceInterface(conn, sig.Path)
	}

	if devIface == w.netbirdIface {
		if newState == nmDeviceStateDisconnected || newState == nmDeviceStateDeactivating || newState == nmDeviceStateFailed {
			handler.OnNetworkEvent(Event{
				Kind:          EventNetBirdInterfaceDisconnected,
				Name:          devIface,
				Reason:        fmt.Sprintf("device state changed %d -> %d reason %d", oldState, newState, reason),
				UserInitiated: true,
			})
		}
	}
}
