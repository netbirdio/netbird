//go:build !android && !ios && !freebsd && !js

// Package updater holds the auto-update domain: the typed State, the
// daemon-SystemEvent metadata schema, and the Holder that caches the latest
// state and broadcasts changes. No Wails dependency.
package updater

import (
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/proto"
)

// EventStateChanged carries the full State snapshot as payload.
const EventStateChanged = "netbird:update:state"

// State is the typed snapshot of the daemon's update situation. Installing is
// driven only by the daemon's progress_window:show event; a UI-side
// Update.Trigger() does not flip it.
type State struct {
	Available  bool   `json:"available"`
	Version    string `json:"version"`
	Enforced   bool   `json:"enforced"`
	Installing bool   `json:"installing"`
}

// Emitter is the broadcast dependency Holder needs; the Wails app.Event
// processor satisfies it.
type Emitter interface {
	Emit(name string, data ...any) bool
}

// Holder caches the latest update State and broadcasts changes.
type Holder struct {
	emitter Emitter

	mu    sync.Mutex
	state State
}

// NewHolder constructs an empty-state Holder. A nil emitter skips the broadcast.
func NewHolder(emitter Emitter) *Holder {
	return &Holder{emitter: emitter}
}

// Get returns a copy of the cached State.
func (h *Holder) Get() State {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.state
}

// OnSystemEvent folds update-related metadata into the cached state, emitting
// EventStateChanged only on an actual change so repeated daemon snapshots
// don't produce redundant pushes.
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
