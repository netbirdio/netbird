//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

// ProfileSwitcher encapsulates the full profile-switching reconnect policy
// so both the tray and the React frontend use identical logic.
//
// Reconnect policy + optimistic-feedback table (driven by prevStatus
// captured from DaemonFeed.Get at SwitchActive entry):
//
//	┌─────────────────┬──────────────────────┬──────────────────────────┬────────────────────┐
//	│ Previous status │ Action               │ Optimistic UI label      │ Suppressed events  │
//	│                 │                      │ shown immediately        │ until new flow     │
//	├─────────────────┼──────────────────────┼──────────────────────────┼────────────────────┤
//	│ Connected       │ Switch + Down + Up   │ Connecting (synthetic)   │ Connected, Idle    │
//	│ Connecting      │ Switch + Down + Up   │ Connecting (unchanged)   │ Connected, Idle    │
//	│ NeedsLogin      │ Switch + Down        │ (no change)              │ —                  │
//	│ LoginFailed     │ Switch + Down        │ (no change)              │ —                  │
//	│ SessionExpired  │ Switch + Down        │ (no change)              │ —                  │
//	│ Idle            │ Switch only          │ (no change)              │ —                  │
//	└─────────────────┴──────────────────────┴──────────────────────────┴────────────────────┘
//
// Only Connected/Connecting trigger the optimistic Connecting paint
// (via DaemonFeed.BeginProfileSwitch): they're the only prevStatuses where
// the daemon emits stale Connected updates (peer count drops as the
// engine tears down) and then Idle, before the new profile's Up
// resumes the stream. Both are swallowed by DaemonFeed.shouldSuppress
// until a status that signals the new flow has begun (Connecting, or
// any of the "Up won't run" terminal states: NeedsLogin / LoginFailed /
// SessionExpired / DaemonUnavailable). The other prevStatuses either
// don't drive Down/Up at all (Idle) or stop after Down (NeedsLogin /
// LoginFailed / SessionExpired) — the resulting Idle is the correct
// terminal state, so no suppression is needed.
//
// Rationale for each Action choice:
//
//	Connected       → Reconnect with the new profile.
//	Connecting      → Stop old retry loop, restart.
//	NeedsLogin      → Clear stale error; user logs in.
//	LoginFailed     → Clear stale error; user logs in.
//	SessionExpired  → Clear stale error; user logs in.
//	Idle            → User chose offline; don't connect.
type ProfileSwitcher struct {
	profiles   *Profiles
	connection *Connection
	feed       *DaemonFeed
}

// NewProfileSwitcher creates a ProfileSwitcher backed by the given services.
// EventProfileChanged is emitted via feed.emitter (same package), so React
// refreshes after a tray-driven switch and vice versa — the daemon does
// not emit a dedicated profile event.
func NewProfileSwitcher(profiles *Profiles, connection *Connection, feed *DaemonFeed) *ProfileSwitcher {
	return &ProfileSwitcher{profiles: profiles, connection: connection, feed: feed}
}

// SwitchActive switches to the named profile applying the reconnect policy.
// All RPCs complete quickly: Up uses async mode so the daemon starts the
// connection attempt and returns immediately; status updates flow via the
// SubscribeStatus stream.
func (s *ProfileSwitcher) SwitchActive(ctx context.Context, p ProfileRef) error {
	prevStatus := ""
	if st, err := s.feed.Get(ctx); err == nil {
		prevStatus = st.Status
	} else {
		log.Warnf("profileswitcher: get status: %v", err)
	}

	wasActive := strings.EqualFold(prevStatus, StatusConnected) ||
		strings.EqualFold(prevStatus, StatusConnecting)
	needsDown := wasActive ||
		strings.EqualFold(prevStatus, StatusNeedsLogin) ||
		strings.EqualFold(prevStatus, StatusLoginFailed) ||
		strings.EqualFold(prevStatus, StatusSessionExpired)

	log.Infof("profileswitcher: switch profile=%q prevStatus=%q wasActive=%v needsDown=%v",
		p.ProfileName, prevStatus, wasActive, needsDown)

	// Optimistic Connecting feedback for tray + React Status page: only
	// when wasActive — those are the prevStatuses where the daemon will
	// emit stale Connected + transient Idle pushes during Down before
	// the new profile's Up resumes the stream (see DaemonFeed godoc for the
	// suppression table). Other prevStatuses already terminate cleanly
	// on Idle, no suppression needed.
	if wasActive {
		s.feed.BeginProfileSwitch()
	}

	if err := s.profiles.Switch(ctx, p); err != nil {
		return fmt.Errorf("switch profile %q: %w", p.ProfileName, err)
	}

	// Mirror the daemon-side switch into the user-side ProfileManager state
	// (~/Library/Application Support/netbird/active_profile on macOS, the
	// equivalent user config dir elsewhere). The CLI's `netbird up` reads
	// from this file (cmd/up.go: pm.GetActiveProfile()) and then sends the
	// resolved name back in the Login/Up RPC — if it diverges from the
	// daemon-side /var/lib/netbird/active_profile.json, the daemon will
	// silently switch its active profile to whatever the CLI sends, so the
	// next CLI `up` after a UI switch reverts the profile. Failures here
	// don't abort the switch (the daemon is the authority; the local
	// mirror is a cache the CLI consults), but they leave the CLI's view
	// stale until the next successful switch — surface as a warning.
	if err := profilemanager.NewProfileManager().SwitchProfile(p.ProfileName); err != nil {
		log.Warnf("profileswitcher: mirror to user-side ProfileManager failed: %v", err)
	}

	if needsDown {
		if err := s.connection.Down(ctx); err != nil {
			log.Errorf("profileswitcher: Down: %v", err)
		}
	}

	if wasActive {
		if err := s.connection.Up(ctx, UpParams(p)); err != nil {
			return fmt.Errorf("reconnect %q: %w", p.ProfileName, err)
		}
	}

	// Fan out the switch to every UI surface. The daemon does not emit a
	// profile event, so without this the React ProfileContext stays on the
	// old profile after a tray-initiated switch (and the tray's profile
	// submenu would lag a React-initiated one, except the tray rebuilds on
	// every status transition).
	if s.feed != nil && s.feed.emitter != nil {
		s.feed.emitter.Emit(EventProfileChanged, p)
	}

	return nil
}
