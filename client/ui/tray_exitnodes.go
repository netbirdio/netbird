//go:build !android && !ios && !freebsd && !js

package main

import (
	"context"
	"net/netip"
	"sort"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/wailsapp/wails/v3/pkg/application"

	"github.com/netbirdio/netbird/client/ui/services"
)

// exitNodeEntry is one Exit Node submenu row; ID is the network's NetID, the Select/Deselect argument.
type exitNodeEntry struct {
	ID       string
	Selected bool
}

// fillExitNodeSubmenu uses a "✓ " prefix with plain Add, not AddCheckbox: Wails
// auto-toggles a checkbox on click before OnClick runs, so the deselect/select
// round-trip would briefly show two checked rows. Callers must hold exitNodesRebuildMu.
func (t *Tray) fillExitNodeSubmenu(nodes []exitNodeEntry) {
	if t.exitNodeSubmenu == nil {
		return
	}
	t.exitNodeSubmenu.Clear()
	for _, n := range nodes {
		id := n.ID
		selected := n.Selected
		label := id
		if selected {
			label = "✓ " + id
		}
		t.exitNodeSubmenu.Add(label).OnClick(func(*application.Context) {
			t.toggleExitNode(id, selected)
		})
	}
}

// refreshExitNodes sources rows from Networks.List() rather than the Status stream
// because only ListNetworks carries the NetID + selected state Select/Deselect need.
// Serialized by exitNodesRebuildMu against overlapping Status pushes.
func (t *Tray) refreshExitNodes() {
	t.exitNodesRebuildMu.Lock()
	defer t.exitNodesRebuildMu.Unlock()

	t.statusMu.Lock()
	connected := t.connected
	t.statusMu.Unlock()

	var nodes []exitNodeEntry
	if connected {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		list, err := t.svc.Networks.List(ctx)
		cancel()
		if err != nil {
			log.Debugf("tray list networks: %v", err)
			return
		}
		nodes = exitNodesFromNetworks(list)
	}

	log.Infof("tray refreshExitNodes: %d exit node(s)", len(nodes))
	for _, n := range nodes {
		log.Infof("tray exit node: id=%q selected=%v", n.ID, n.Selected)
	}

	t.exitNodesMu.Lock()
	changed := !equalExitNodes(nodes, t.exitNodes)
	t.exitNodes = nodes
	t.exitNodesMu.Unlock()

	// relayoutMenu repaints from the cached entries, so the old exitNodeItem needs no poking here.
	if changed {
		t.relayoutMenu()
	}
}

// toggleExitNode uses append=true: append=false would drop the whole current
// selection (default-on semantics), turning off every other routed network the
// user had enabled. Mutual exclusion of exit nodes is enforced daemon-side.
func (t *Tray) toggleExitNode(id string, selected bool) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		params := services.SelectNetworksParams{NetworkIDs: []string{id}, Append: true, All: false}
		var err error
		if selected {
			err = t.svc.Networks.Deselect(ctx, params)
		} else {
			err = t.svc.Networks.Select(ctx, params)
		}
		if err != nil {
			log.Errorf("tray toggle exit node %q: %v", id, err)
			t.notifyError(t.loc.T("notify.error.exitNode", "name", id))
			return
		}
		t.refreshExitNodes()
	}()
}

// exitNodesFromNetworks keeps only networks whose range is a default route: those are the exit-node candidates.
func exitNodesFromNetworks(networks []services.Network) []exitNodeEntry {
	out := []exitNodeEntry{}
	for _, n := range networks {
		if !rangeIsDefaultRoute(n.Range) {
			continue
		}
		out = append(out, exitNodeEntry{ID: n.ID, Selected: n.Selected})
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i].ID) < strings.ToLower(out[j].ID)
	})
	return out
}

// rangeIsDefaultRoute reports whether r contains a default route. The daemon may
// comma-join a v4+v6 pair ("0.0.0.0/0, ::/0"), so each part is parsed rather than string-compared.
func rangeIsDefaultRoute(r string) bool {
	for _, part := range strings.Split(r, ",") {
		pref, err := netip.ParsePrefix(strings.TrimSpace(part))
		if err != nil {
			continue
		}
		if pref.Bits() == 0 && pref.Addr().IsUnspecified() {
			return true
		}
	}
	return false
}

func equalExitNodes(a, b []exitNodeEntry) bool {
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
