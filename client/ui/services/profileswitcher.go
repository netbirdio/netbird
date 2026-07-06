//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

// ProfileSwitcher holds the reconnect policy shared by the tray and React
// frontend so both flip profiles identically. The policy keys off prevStatus
// from DaemonFeed.Get at SwitchActive entry:
//
//	Connected/Connecting → Switch + Down + Up; optimistic Connecting paint.
//	NeedsLogin/LoginFailed/SessionExpired → Switch + Down; clear stale error for re-login.
//	Idle → Switch only.
type ProfileSwitcher struct {
	profiles   *Profiles
	connection *Connection
	feed       *DaemonFeed
}

func NewProfileSwitcher(profiles *Profiles, connection *Connection, feed *DaemonFeed) *ProfileSwitcher {
	return &ProfileSwitcher{profiles: profiles, connection: connection, feed: feed}
}

// SwitchActive switches to the named profile applying the reconnect policy.
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

	// Optimistic Connecting paint only when wasActive: those prevStatuses emit
	// stale Connected + transient Idle pushes during Down that must be
	// suppressed until Up resumes the stream (see DaemonFeed suppression table).
	if wasActive {
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

	if wasActive {
		if err := s.connection.Up(ctx, UpParams(p)); err != nil {
			return fmt.Errorf("reconnect %q: %w", p.ProfileName, err)
		}
	}

	// The daemon emits no profile event, so fan out ourselves or the React
	// ProfileContext stays on the old profile after a tray-initiated switch.
	if s.feed != nil && s.feed.emitter != nil {
		s.feed.emitter.Emit(EventProfileChanged, p)
	}

	return nil
}
