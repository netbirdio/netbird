//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
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
// It returns after the Switch RPC completes so the caller can refresh its UI
// immediately; Down and Up run in a background goroutine.
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

	go func() {
		bgCtx := context.Background()
		if needsDown {
			if err := s.connection.Down(bgCtx); err != nil {
				log.Errorf("profileswitcher: Down: %v", err)
			}
		}
		if wasActive {
			if err := s.connection.Up(bgCtx, UpParams{
				ProfileName: p.ProfileName,
				Username:    p.Username,
			}); err != nil {
				log.Errorf("profileswitcher: Up %s: %v", p.ProfileName, err)
			}
		}
	}()

	return nil
}
