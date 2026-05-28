//go:build !android && !ios && !freebsd && !js

package main

import (
	"runtime"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/ui/services"
)

func (t *Tray) applyIcon() {
	t.statusMu.Lock()
	connected := t.connected
	statusLabel := t.lastStatus
	t.statusMu.Unlock()
	hasUpdate := false
	if t.updater != nil {
		hasUpdate = t.updater.hasUpdate()
	}

	log.Infof("tray applyIcon: connected=%v hasUpdate=%v status=%q goos=%s",
		connected, hasUpdate, statusLabel, runtime.GOOS)

	icon, dark := t.iconForState()
	if runtime.GOOS == "darwin" {
		t.tray.SetTemplateIcon(icon)
		return
	}
	t.tray.SetIcon(icon)
	if dark != nil {
		t.tray.SetDarkModeIcon(dark)
	}
}

func (t *Tray) iconForState() (icon, dark []byte) {
	t.statusMu.Lock()
	connected := t.connected
	statusLabel := t.lastStatus
	t.statusMu.Unlock()
	hasUpdate := false
	if t.updater != nil {
		hasUpdate = t.updater.hasUpdate()
	}

	connecting := strings.EqualFold(statusLabel, services.StatusConnecting)
	errored := strings.EqualFold(statusLabel, statusError) ||
		strings.EqualFold(statusLabel, services.StatusDaemonUnavailable)
	needsLogin := strings.EqualFold(statusLabel, services.StatusNeedsLogin) ||
		strings.EqualFold(statusLabel, services.StatusSessionExpired) ||
		strings.EqualFold(statusLabel, services.StatusLoginFailed)

	if runtime.GOOS == "darwin" {
		switch {
		case connecting:
			return iconConnectingMacOS, nil
		case errored:
			return iconErrorMacOS, nil
		case needsLogin:
			return iconNeedsLoginMacOS, nil
		case connected && hasUpdate:
			return iconUpdateConnectedMacOS, nil
		case connected:
			return iconConnectedMacOS, nil
		case hasUpdate:
			return iconUpdateDisconnectedMacOS, nil
		default:
			return iconDisconnectedMacOS, nil
		}
	}

	switch {
	case connecting:
		return iconConnecting, nil
	case errored:
		return iconError, nil
	case needsLogin:
		return iconNeedsLogin, nil
	case connected && hasUpdate:
		return iconUpdateConnected, nil
	case connected:
		return iconConnected, iconConnectedDark
	case hasUpdate:
		return iconUpdateDisconnected, nil
	default:
		return iconDisconnected, nil
	}
}
