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

// exitNodeEntry is one selectable row in the Exit Node submenu. ID is the
// network's NetID — both the row label and the argument the Select/Deselect
// RPCs take; Selected drives the ✓ prefix.
type exitNodeEntry struct {
	ID       string
	Selected bool
}

// fillExitNodeSubmenu paints one clickable row per exit-node candidate into
// the (freshly built) Exit Node submenu. Each row carries the network's NetID
// and its selected state from ListNetworks; clicking toggles it via
// toggleExitNode. The active node is marked with a "✓ " prefix using a plain
// Add rather than AddCheckbox for the same reason as fillProfileSubmenu —
// Wails auto-toggles a checkbox's state on click before the OnClick handler
// runs, so the deselect/select round-trip would briefly show two checked rows.
// Pure UI: it never calls SetMenu — relayoutMenu owns the single SetMenu that
// pushes the whole tree. Callers must hold exitNodesRebuildMu so concurrent
// rebuilds can't race the submenu's item slice.
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

// refreshExitNodes re-fetches the routed-network list from the daemon and
// repaints the Exit Node submenu. Sourcing the rows from Networks.List() (not
// the Status stream) is what makes them selectable: the stream only ships peer
// FQDNs, whereas ListNetworks returns the NetID + selected state the
// Select/Deselect RPCs need. Serialized by exitNodesRebuildMu so overlapping
// Status pushes can't race the submenu rebuild. Owns the parent item's
// enablement: greyed unless the tunnel is up and at least one candidate exists.
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

	// relayoutMenu rebuilds the whole tree (allocating a fresh exitNodeItem) and
	// repaints the parent's enablement from the cached entries we just stored,
	// so there is no need to poke the old exitNodeItem here.
	if changed {
		t.relayoutMenu()
	}
}

// toggleExitNode activates or deactivates one exit node by NetID. Exit nodes
// are mutually exclusive, but enforcement of that lives daemon-side: the
// SelectNetworks handler deselects every other exit node when this Select
// activates one. So Select uses append=true — append=false would tell the
// RouteSelector to drop the whole current selection (default-on semantics),
// which also turns off every non-exit routed network the user had enabled.
// Mirrors the frontend's toggleExitNode semantics. Runs the RPC off the
// menu-click goroutine and re-fetches so the ✓ moves to the new selection.
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

// exitNodesFromNetworks filters the daemon's routed-network list down to
// exit-node candidates (a default-route range) and maps them to selectable
// rows. Sorted case-insensitively by ID so the submenu reads alphabetically.
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

// rangeIsDefaultRoute reports whether a Network.Range string contains an IPv4
// or IPv6 default route. The daemon may merge a v4+v6 exit pair into a single
// comma-joined range ("0.0.0.0/0, ::/0"), so we split and check each part,
// matching by Bits()==0 && unspecified rather than a literal string compare.
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
