//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

// ProfileSwitcher encapsulates the full profile-switching reconnect policy so
// both the tray and the React frontend use identical logic.
//
// Reconnect policy:
//
//	┌─────────────────┬──────────────────────┬────────────────────────────────────┐
//	│ Previous status │ Action               │ Rationale                          │
//	├─────────────────┼──────────────────────┼────────────────────────────────────┤
//	│ Connected       │ Switch + Down + Up   │ Reconnect with the new profile.    │
//	│ Connecting      │ Switch + Down + Up   │ Stop old retry loop, restart.      │
//	│ NeedsLogin      │ Switch + Down        │ Clear stale error; user logs in.   │
//	│ LoginFailed     │ Switch + Down        │ Clear stale error; user logs in.   │
//	│ SessionExpired  │ Switch + Down        │ Clear stale error; user logs in.   │
//	│ Idle            │ Switch only          │ User chose offline; don't connect. │
//	└─────────────────┴──────────────────────┴────────────────────────────────────┘
type ProfileSwitcher struct {
	profiles   *Profiles
	connection *Connection
	peers      *Peers
}

// NewProfileSwitcher creates a ProfileSwitcher backed by the given services.
func NewProfileSwitcher(profiles *Profiles, connection *Connection, peers *Peers) *ProfileSwitcher {
	return &ProfileSwitcher{profiles: profiles, connection: connection, peers: peers}
}

// SwitchActive switches to the named profile applying the reconnect policy.
// All RPCs complete quickly: Up uses async mode so the daemon starts the
// connection attempt and returns immediately; status updates flow via the
// SubscribeStatus stream.
func (s *ProfileSwitcher) SwitchActive(ctx context.Context, p ProfileRef) error {
	prevStatus := ""
	if st, err := s.peers.Get(ctx); err == nil {
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

	return nil
}
