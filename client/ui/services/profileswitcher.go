//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

// ProfileSwitcher holds the switch policy shared by the tray and React
// frontend so both flip profiles identically. SwitchActive (plain selection:
// header dropdown, tray submenu) always connects after the switch;
// SwitchActiveNoConnect (manage-profiles screen) never does, so the user can
// still adjust the management URL before connecting. prevStatus from
// DaemonFeed.Get at entry only decides the teardown:
//
//	Connected/Connecting/NeedsLogin/LoginFailed/SessionExpired → Down first.
//	Idle → no Down.
type ProfileSwitcher struct {
	profiles   *Profiles
	connection *Connection
	feed       *DaemonFeed
}

func NewProfileSwitcher(profiles *Profiles, connection *Connection, feed *DaemonFeed) *ProfileSwitcher {
	return &ProfileSwitcher{profiles: profiles, connection: connection, feed: feed}
}

// SwitchActive switches to the named profile and always connects afterwards.
func (s *ProfileSwitcher) SwitchActive(ctx context.Context, p ProfileRef) error {
	return s.switchActive(ctx, p, true)
}

// SwitchActiveNoConnect switches to the named profile without connecting,
// tearing down any existing connection first.
func (s *ProfileSwitcher) SwitchActiveNoConnect(ctx context.Context, p ProfileRef) error {
	return s.switchActive(ctx, p, false)
}

func (s *ProfileSwitcher) switchActive(ctx context.Context, p ProfileRef, connect bool) error {
	prevStatus := ""
	if s.feed != nil {
		if st, err := s.feed.Get(ctx); err == nil {
			prevStatus = st.Status
		} else {
			log.Warnf("profileswitcher: get status: %v", err)
		}
	}

	needsDown := strings.EqualFold(prevStatus, StatusConnected) ||
		strings.EqualFold(prevStatus, StatusConnecting) ||
		strings.EqualFold(prevStatus, StatusNeedsLogin) ||
		strings.EqualFold(prevStatus, StatusLoginFailed) ||
		strings.EqualFold(prevStatus, StatusSessionExpired)

	log.Infof("profileswitcher: switch profile=%q prevStatus=%q connect=%v needsDown=%v",
		p.ProfileName, prevStatus, connect, needsDown)

	// Optimistic Connecting paint plus stale-push suppression during Down (see
	// DaemonFeed suppression table); also arms the login-watch that pops
	// browser-login when the new profile turns out to need SSO.
	if connect && s.feed != nil {
		s.feed.BeginProfileSwitch()
	}

	resolvedID, err := s.profiles.Switch(ctx, p)
	if err != nil {
		return fmt.Errorf("switch profile %q: %w", p.ProfileName, err)
	}

	// Mirror into the user-side ProfileManager state: the CLI's `netbird up`
	// reads this file and sends the ID back in the Up RPC, so if it diverges
	// the daemon reverts the UI switch on the next CLI `up`. Best-effort — the
	// daemon is authoritative; a failure only leaves the CLI's view stale.
	// Use the daemon-resolved ID rather than the handle we sent, since the
	// on-disk state is keyed by ID, not display name.
	if err := profilemanager.NewProfileManager().SwitchProfile(profilemanager.ID(resolvedID)); err != nil {
		log.Warnf("profileswitcher: mirror to user-side ProfileManager failed: %v", err)
	}

	if needsDown {
		if err := s.connection.Down(ctx); err != nil {
			log.Errorf("profileswitcher: Down: %v", err)
		}
	}

	if connect {
		if err := s.connection.Up(ctx, UpParams(p)); err != nil {
			return fmt.Errorf("connect %q: %w", p.ProfileName, err)
		}
	}

	// The daemon emits no profile event, so fan out ourselves or the React
	// ProfileContext stays on the old profile after a tray-initiated switch.
	if s.feed != nil && s.feed.emitter != nil {
		s.feed.emitter.Emit(EventProfileChanged, p)
	}

	return nil
}
