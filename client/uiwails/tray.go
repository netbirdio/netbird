//go:build !(linux && 386)

package main

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/wailsapp/wails/v3/pkg/application"

	"github.com/netbirdio/netbird/client/uiwails/services"
)

const statusPollInterval = 5 * time.Second

// trayManager manages the system tray state and menu.
type trayManager struct {
	app    *application.App
	window *application.WebviewWindow
	tray   *application.SystemTray
	menu   *application.Menu

	connSvc     *services.ConnectionService
	settingsSvc *services.SettingsService
	networkSvc  *services.NetworkService
	profileSvc  *services.ProfileService

	mu           sync.Mutex
	statusItem   *application.MenuItem
	exitNodeMenu *application.Menu

	// toggle items tracked for updating checked state
	sshItem           *application.MenuItem
	autoConnectItem   *application.MenuItem
	rosenpassItem     *application.MenuItem
	lazyConnItem      *application.MenuItem
	blockInboundItem  *application.MenuItem
	notificationsItem *application.MenuItem

	exitNodeItems  []*application.MenuItem
	exitNodeStates []exitNodeState
}

type exitNodeState struct {
	id       string
	selected bool
}

func newTrayManager(
	app *application.App,
	window *application.WebviewWindow,
	connSvc *services.ConnectionService,
	settingsSvc *services.SettingsService,
	networkSvc *services.NetworkService,
	profileSvc *services.ProfileService,
) *trayManager {
	return &trayManager{
		app:         app,
		window:      window,
		connSvc:     connSvc,
		settingsSvc: settingsSvc,
		networkSvc:  networkSvc,
		profileSvc:  profileSvc,
	}
}

// Setup creates and attaches the system tray.
func (t *trayManager) Setup(icon []byte) {
	t.tray = t.app.SystemTray.New()
	t.tray.SetIcon(icon)

	t.menu = t.buildMenu()
	t.tray.AttachWindow(t.window).WindowOffset(5).SetMenu(t.menu)

	// Load initial toggle states from config.
	go t.refreshToggleStates()

	// Start status polling goroutine.
	go t.pollStatus(context.Background())
}

func (t *trayManager) buildMenu() *application.Menu {
	menu := t.app.NewMenu()

	// Status label (disabled, informational).
	t.statusItem = menu.Add("Status: Disconnected")
	t.statusItem.SetEnabled(false)
	menu.AddSeparator()

	// Connect / Disconnect.
	menu.Add("Connect").OnClick(func(_ *application.Context) {
		go func() {
			if err := t.connSvc.Connect(); err != nil {
				log.Errorf("connect: %v", err)
			}
		}()
	})
	menu.Add("Disconnect").OnClick(func(_ *application.Context) {
		go func() {
			if err := t.connSvc.Disconnect(); err != nil {
				log.Errorf("disconnect: %v", err)
			}
		}()
	})
	menu.AddSeparator()

	// Toggle checkboxes.
	t.sshItem = menu.AddCheckbox("Allow SSH connections", false)
	t.sshItem.OnClick(func(ctx *application.Context) {
		enabled := ctx.ClickedMenuItem().Checked()
		go func() {
			if err := t.settingsSvc.ToggleSSH(enabled); err != nil {
				log.Errorf("toggle SSH: %v", err)
				t.sshItem.SetChecked(!enabled)
			}
		}()
	})

	t.autoConnectItem = menu.AddCheckbox("Connect automatically when service starts", false)
	t.autoConnectItem.OnClick(func(ctx *application.Context) {
		enabled := ctx.ClickedMenuItem().Checked()
		go func() {
			if err := t.settingsSvc.ToggleAutoConnect(enabled); err != nil {
				log.Errorf("toggle auto-connect: %v", err)
				t.autoConnectItem.SetChecked(!enabled)
			}
		}()
	})

	t.rosenpassItem = menu.AddCheckbox("Enable post-quantum security via Rosenpass", false)
	t.rosenpassItem.OnClick(func(ctx *application.Context) {
		enabled := ctx.ClickedMenuItem().Checked()
		go func() {
			if err := t.settingsSvc.ToggleRosenpass(enabled); err != nil {
				log.Errorf("toggle Rosenpass: %v", err)
				t.rosenpassItem.SetChecked(!enabled)
			}
		}()
	})

	t.lazyConnItem = menu.AddCheckbox("[Experimental] Enable lazy connections", false)
	t.lazyConnItem.OnClick(func(ctx *application.Context) {
		enabled := ctx.ClickedMenuItem().Checked()
		go func() {
			if err := t.settingsSvc.ToggleLazyConn(enabled); err != nil {
				log.Errorf("toggle lazy connections: %v", err)
				t.lazyConnItem.SetChecked(!enabled)
			}
		}()
	})

	t.blockInboundItem = menu.AddCheckbox("Block inbound connections", false)
	t.blockInboundItem.OnClick(func(ctx *application.Context) {
		enabled := ctx.ClickedMenuItem().Checked()
		go func() {
			if err := t.settingsSvc.ToggleBlockInbound(enabled); err != nil {
				log.Errorf("toggle block inbound: %v", err)
				t.blockInboundItem.SetChecked(!enabled)
			}
		}()
	})

	t.notificationsItem = menu.AddCheckbox("Enable notifications", true)
	t.notificationsItem.OnClick(func(ctx *application.Context) {
		enabled := ctx.ClickedMenuItem().Checked()
		go func() {
			if err := t.settingsSvc.ToggleNotifications(enabled); err != nil {
				log.Errorf("toggle notifications: %v", err)
				t.notificationsItem.SetChecked(!enabled)
			}
		}()
	})

	menu.AddSeparator()

	// Exit Node submenu.
	t.exitNodeMenu = menu.AddSubmenu("Exit Node")
	t.exitNodeMenu.Add("No exit nodes").SetEnabled(false)

	menu.AddSeparator()

	// Navigation items — navigate React SPA.
	menu.Add("Status").OnClick(func(_ *application.Context) {
		t.window.EmitEvent("navigate", "/")
		t.window.Show()
	})
	menu.Add("Settings").OnClick(func(_ *application.Context) {
		t.window.EmitEvent("navigate", "/settings")
		t.window.Show()
	})
	menu.Add("Peers").OnClick(func(_ *application.Context) {
		t.window.EmitEvent("navigate", "/peers")
		t.window.Show()
	})
	menu.Add("Networks").OnClick(func(_ *application.Context) {
		t.window.EmitEvent("navigate", "/networks")
		t.window.Show()
	})
	menu.Add("Profiles").OnClick(func(_ *application.Context) {
		t.window.EmitEvent("navigate", "/profiles")
		t.window.Show()
	})
	menu.Add("Debug").OnClick(func(_ *application.Context) {
		t.window.EmitEvent("navigate", "/debug")
		t.window.Show()
	})
	menu.Add("Update").OnClick(func(_ *application.Context) {
		t.window.EmitEvent("navigate", "/update")
		t.window.Show()
	})

	menu.AddSeparator()

	menu.Add("Quit").OnClick(func(_ *application.Context) {
		t.app.Quit()
	})

	return menu
}

// pollStatus polls the daemon status every statusPollInterval and updates the tray.
// Exit nodes are refreshed every 10 cycles (~20 seconds).
func (t *trayManager) pollStatus(ctx context.Context) {
	ticker := time.NewTicker(statusPollInterval)
	defer ticker.Stop()

	var cycle int
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			status, err := t.connSvc.GetStatus()
			if err != nil {
				log.Warnf("pollStatus: failed to get status: %v", err)
				continue
			}
			log.Debugf("pollStatus: status=%q ip=%q fqdn=%q peers=%d",
				status.Status, status.IP, status.Fqdn, status.ConnectedPeers)
			t.updateStatus(status)

			cycle++
			if cycle%10 == 0 {
				go t.refreshExitNodes()
			}
		}
	}
}

func (t *trayManager) updateStatus(status *services.StatusInfo) {
	label := fmt.Sprintf("Status: %s", status.Status)
	if status.IP != "" {
		label += fmt.Sprintf(" (%s)", status.IP)
	}
	t.statusItem.SetLabel(label)
	t.menu.Update()

	// Update tray icon based on status.
	icon := iconForStatus(status.Status)
	if icon != nil {
		t.tray.SetIcon(icon)
	}

	// Emit event so the React frontend can update live.
	log.Debugf("updateStatus: emitting status-changed event: status=%q ip=%q", status.Status, status.IP)
	t.window.EmitEvent("status-changed", status)
}

func (t *trayManager) refreshToggleStates() {
	cfg, err := t.settingsSvc.GetConfig()
	if err != nil {
		log.Debugf("refresh toggle states: %v", err)
		return
	}

	t.sshItem.SetChecked(cfg.ServerSSHAllowed)
	t.autoConnectItem.SetChecked(!cfg.DisableAutoConnect)
	t.rosenpassItem.SetChecked(cfg.RosenpassEnabled)
	t.lazyConnItem.SetChecked(cfg.LazyConnectionEnabled)
	t.blockInboundItem.SetChecked(cfg.BlockInbound)
	t.notificationsItem.SetChecked(!cfg.DisableNotifications)
	t.menu.Update()
}

func (t *trayManager) refreshExitNodes() {
	exitNodes, err := t.networkSvc.ListExitNodes()
	if err != nil {
		log.Debugf("refresh exit nodes: %v", err)
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	t.rebuildExitNodeMenu(exitNodes)
}

func (t *trayManager) rebuildExitNodeMenu(exitNodes []services.NetworkInfo) {
	// Sort exit nodes by ID for stable ordering.
	sort.Slice(exitNodes, func(i, j int) bool {
		return exitNodes[i].ID < exitNodes[j].ID
	})

	// Check if state has changed.
	newStates := make([]exitNodeState, 0, len(exitNodes))
	for _, n := range exitNodes {
		newStates = append(newStates, exitNodeState{id: n.ID, selected: n.Selected})
	}

	if statesEqual(t.exitNodeStates, newStates) {
		return
	}
	t.exitNodeStates = newStates

	// Rebuild the exit node submenu from scratch.
	// Wails v3 doesn't have a RemoveAll, so we recreate the submenu reference.
	for _, item := range t.exitNodeItems {
		item.SetHidden(true)
	}
	t.exitNodeItems = nil

	if len(exitNodes) == 0 {
		t.menu.Update()
		return
	}

	var hasSelected bool
	for _, node := range exitNodes {
		n := node // capture
		item := t.exitNodeMenu.AddCheckbox(n.ID, n.Selected)
		item.OnClick(func(_ *application.Context) {
			go t.toggleExitNode(n.ID)
		})
		t.exitNodeItems = append(t.exitNodeItems, item)
		if n.Selected {
			hasSelected = true
		}
	}

	if hasSelected {
		t.exitNodeMenu.AddSeparator()
		deselectAll := t.exitNodeMenu.Add("Deselect All")
		deselectAll.OnClick(func(_ *application.Context) {
			go t.deselectAllExitNodes()
		})
		t.exitNodeItems = append(t.exitNodeItems, deselectAll)
	}

	t.menu.Update()
}

func (t *trayManager) toggleExitNode(id string) {
	exitNodes, err := t.networkSvc.ListExitNodes()
	if err != nil {
		log.Errorf("list exit nodes: %v", err)
		return
	}

	var target *services.NetworkInfo
	var selectedOtherIDs []string

	for i, n := range exitNodes {
		if n.ID == id {
			cp := exitNodes[i]
			target = &cp
		} else if n.Selected {
			selectedOtherIDs = append(selectedOtherIDs, n.ID)
		}
	}

	// Deselect all other selected exit nodes.
	if len(selectedOtherIDs) > 0 {
		if err := t.networkSvc.DeselectNetworks(selectedOtherIDs); err != nil {
			log.Errorf("deselect exit nodes: %v", err)
		}
	}

	if target != nil && !target.Selected {
		if err := t.networkSvc.SelectNetwork(id); err != nil {
			log.Errorf("select exit node: %v", err)
		}
	} else if target != nil && target.Selected && len(selectedOtherIDs) == 0 {
		// Node is the only selected one — deselect it.
		if err := t.networkSvc.DeselectNetwork(id); err != nil {
			log.Errorf("deselect exit node: %v", err)
		}
	}

	t.refreshExitNodes()
}

func (t *trayManager) deselectAllExitNodes() {
	exitNodes, err := t.networkSvc.ListExitNodes()
	if err != nil {
		log.Errorf("list exit nodes for deselect all: %v", err)
		return
	}

	var ids []string
	for _, n := range exitNodes {
		if n.Selected {
			ids = append(ids, n.ID)
		}
	}

	if len(ids) > 0 {
		if err := t.networkSvc.DeselectNetworks(ids); err != nil {
			log.Errorf("deselect all exit nodes: %v", err)
		}
	}

	t.refreshExitNodes()
}

func statesEqual(a, b []exitNodeState) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
