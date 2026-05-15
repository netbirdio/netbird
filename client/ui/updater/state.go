//go:build !android && !ios && !freebsd && !js

// Package updater carries the auto-update domain: the typed State the UI
// renders, the daemon-SystemEvent metadata schema, and the Holder that
// caches the latest state and broadcasts changes. Mirrors the layout of
// client/ui/i18n and client/ui/preferences — no Wails dependency, just an
// optional Emitter interface so callers can pass either the Wails event
// processor or a fake in tests.
package updater

import (
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/proto"
)

// EventStateChanged is the single Wails event the frontend and tray
// subscribe to. The payload is the full State snapshot, so consumers
// never need to combine multiple events to know what to render.
const EventStateChanged = "netbird:update:state"

// State is the typed snapshot of the daemon's update situation, covering
// the three branches the UI cares about:
//
//   - Disabled / opt-in: Available=true, Enforced=false, Installing=false.
//     Tray shows "Download latest", frontend shows a "Get installer" hint
//     pointing at GitHub.
//   - Enforced, user-driven: Available=true, Enforced=true, Installing=false.
//     Tray shows "Install version X", frontend shows the install banner.
//   - Forced, daemon already installing: Available=true, Enforced=true,
//     Installing=true. Both surfaces show the install-in-progress UI.
//
// Installing is driven only by the daemon's progress_window:show event;
// a UI-side Update.Trigger() does not flip it. The frontend tracks its own
// "Trigger() in flight" state for the enforced flow.
type State struct {
	Available  bool   `json:"available"`
	Version    string `json:"version"`
	Enforced   bool   `json:"enforced"`
	Installing bool   `json:"installing"`
}

// Emitter is the dependency Holder needs to broadcast changes. The Wails
// app.Event processor satisfies this; tests pass nil or a fake. Same shape
// the preferences package uses, intentionally — both are "broadcast to the
// frontend" hooks with no other contract.
type Emitter interface {
	Emit(name string, data ...any) bool
}

// Holder caches the latest update State and broadcasts changes. Fed by
// services.Peers, which forwards every daemon SystemEvent here via
// OnSystemEvent. The state is read by the Wails-bound services.Update
// facade (Get) and pushed to subscribers via the Emitter.
type Holder struct {
	emitter Emitter

	mu    sync.Mutex
	state State
}

// NewHolder constructs an empty-state Holder. The emitter is optional —
// pass nil in tests to skip the broadcast.
func NewHolder(emitter Emitter) *Holder {
	return &Holder{emitter: emitter}
}

// Get returns a copy of the cached State. Used by the Wails facade so the
// frontend can pull the current value on mount before its push subscription
// has anything to deliver.
func (h *Holder) Get() State {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.state
}

// OnSystemEvent inspects the daemon's SystemEvent metadata for the three
// update-related keys (new_version_available, enforced, progress_window
// plus version) and folds the result into the cached state. Emits
// EventStateChanged only when the state actually changed, so subscribers
// do not see redundant pushes when the daemon repeats a snapshot.
//
// The metadata schema is owned here and nowhere else — neither Peers nor
// the tray nor the frontend reaches into ev.Metadata directly.
func (h *Holder) OnSystemEvent(ev *proto.SystemEvent) {
	md := ev.GetMetadata()
	if len(md) == 0 {
		return
	}

	h.mu.Lock()
	changed := false
	if v, ok := md["new_version_available"]; ok {
		_, enforced := md["enforced"]
		if !h.state.Available || h.state.Version != v || h.state.Enforced != enforced {
			h.state.Available = true
			h.state.Version = v
			h.state.Enforced = enforced
			changed = true
		}
	}
	if md["progress_window"] == "show" {
		if !h.state.Installing {
			h.state.Installing = true
			changed = true
		}
		if v, ok := md["version"]; ok && v != "" && h.state.Version != v {
			h.state.Version = v
			h.state.Available = true
			changed = true
		}
	}
	snap := h.state
	h.mu.Unlock()

	if !changed {
		return
	}
	log.Infof("update state: available=%v version=%q enforced=%v installing=%v",
		snap.Available, snap.Version, snap.Enforced, snap.Installing)
	if h.emitter != nil {
		h.emitter.Emit(EventStateChanged, snap)
	}
}
