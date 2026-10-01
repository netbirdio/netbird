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
	if runtime.GOOS == "linux" {
		// Wails' Linux SNI backend ignores SetDarkModeIcon (last write wins
		// over SetIcon), so iconForState already picked the silhouette by
		// panel theme; push that single icon.
		t.tray.SetIcon(icon)
		return
	}
	t.tray.SetIcon(icon)
	if dark != nil {
		t.tray.SetDarkModeIcon(dark)
	}
}

// panelIsDark defaults to true when no detector is wired (panelDark nil —
// non-Linux or portal unavailable), matching the common dark Linux panel.
func (t *Tray) panelIsDark() bool {
	if t.panelDark == nil {
		return true
	}
	return t.panelDark()
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

	if runtime.GOOS == "linux" {
		// Theme resolved here (black for light panel, white for dark) since
		// the SNI backend can't switch per theme (see applyIcon); second
		// return is unused on Linux.
		dark := t.panelIsDark()
		pick := func(black, white []byte) ([]byte, []byte) {
			if dark {
				return white, nil
			}
			return black, nil
		}
		switch {
		case connecting:
			return pick(iconConnectingMono, iconConnectingMonoDark)
		case errored:
			return pick(iconErrorMono, iconErrorMonoDark)
		case needsLogin:
			return pick(iconNeedsLoginMono, iconNeedsLoginMonoDark)
		case connected && hasUpdate:
			return pick(iconUpdateConnectedMono, iconUpdateConnectedMonoDark)
		case connected:
			return pick(iconConnectedMono, iconConnectedMonoDark)
		case hasUpdate:
			return pick(iconUpdateDisconnectedMono, iconUpdateDisconnectedMonoDark)
		default:
			return pick(iconDisconnectedMono, iconDisconnectedMonoDark)
		}
	}

	// Windows: colored PNGs.
	switch {
	case connecting:
		return iconConnecting, iconConnectingDark
	case errored:
		return iconError, iconErrorDark
	case needsLogin:
		return iconNeedsLogin, iconNeedsLogin
	case connected && hasUpdate:
		return iconUpdateConnected, iconUpdateConnectedDark
	case connected:
		return iconConnected, iconConnectedDark
	case hasUpdate:
		return iconUpdateDisconnected, iconUpdateDisconnectedDark
	default:
		return iconDisconnected, iconDisconnected
	}
}
