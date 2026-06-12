//go:build !android && !ios && !freebsd && !js

package main

import (
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/wailsapp/wails/v3/pkg/application"

	"github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/client/ui/authsession"
	"github.com/netbirdio/netbird/client/ui/services"
)

// onSystemEvent fires an OS notification for daemon SystemEvents that carry
// a user-facing message, mirroring the legacy event.Manager behaviour: gated
// by the user's "Notifications" toggle, with CRITICAL events bypassing the
// gate. Update-related events are skipped here because trayUpdater produces
// its own richer notification when EventUpdateState fires.
func (t *Tray) onSystemEvent(ev *application.CustomEvent) {
	se, ok := ev.Data.(services.SystemEvent)
	if !ok {
		return
	}
	// config_changed: the daemon re-applied its effective config (engine
	// spawn, Up, or MDM policy diff) and signals the UI to re-sync. It
	// carries no UserMessage, so it must be handled before the user-facing
	// message gate below. Re-fetch the feature kill switches (DisableProfiles
	// / DisableNetworks) and the notifications gate so CLI- or MDM-driven
	// changes reflect in the tray without a periodic poll. This replaces the
	// legacy Fyne UI's 2s GetFeatures poll.
	if se.Category == "system" && se.Metadata[proto.MetadataTypeKey] == proto.MetadataTypeConfigChanged {
		log.Infof("config_changed event received (source=%s); refreshing tray restrictions", se.Metadata[proto.MetadataSourceKey])
		go t.refreshRestrictions()
		go t.loadConfig()
		// An MDM-driven config change gets a user-facing toast so the
		// operator knows their IT policy was applied. The daemon also
		// emits a separate "policy_applied" event carrying an English
		// UserMessage, but that text has no locale context — it's
		// suppressed in shouldSkipSystemEvent and the tray builds the
		// localised toast here instead. Other sources (startup, up_rpc)
		// stay silent, matching the daemon's empty-UserMessage intent.
		// Gated by the notifications toggle like every other INFO event.
		if se.Metadata[proto.MetadataSourceKey] == proto.MetadataSourceMDM {
			t.profileMu.Lock()
			enabled := t.notificationsEnabled
			t.profileMu.Unlock()
			if enabled {
				t.notify(
					t.loc.T("notify.mdm.policyApplied.title"),
					t.loc.T("notify.mdm.policyApplied.body"),
					notifyIDMDMPolicy,
				)
			}
		}
		return
	}
	// Session-warning and deadline-rejected events carry no UserMessage —
	// the tray builds the localised notification body locally from metadata.
	// Every other event needs a non-empty UserMessage to show anything meaningful.
	isSessionWarning := se.Metadata[authsession.MetaWarning] == "true"
	isDeadlineRejected := se.Metadata[authsession.MetaDeadlineRejected] != ""
	if !isSessionWarning && !isDeadlineRejected && se.UserMessage == "" {
		return
	}
	if shouldSkipSystemEvent(se) {
		return
	}

	critical := se.Severity == "critical"
	t.profileMu.Lock()
	enabled := t.notificationsEnabled
	t.profileMu.Unlock()
	if !enabled && !critical {
		return
	}

	// Session-warning events come in two flavours; detect via the stable
	// metadata flags rather than category/severity so a future reword on
	// the daemon side still routes here.
	//   - T-WarningLead (MetaSessionWarning + no MetaSessionFinal) →
	//     interactive "Extend now / Dismiss" OS notification. Title and
	//     body are built locally from i18n + metadata so the text follows
	//     the active UI language regardless of what the daemon (which has
	//     no locale context) writes into UserMessage.
	//   - T-FinalWarningLead (MetaSessionFinal=true) → auto-open the
	//     SessionExpiration dialog. No OS notification here; the
	//     dialog is the last-chance reminder, doubling up would be noise.
	if isDeadlineRejected {
		t.notify(
			t.loc.T("notify.sessionDeadlineRejected.title"),
			t.loc.T("notify.sessionDeadlineRejected.body"),
			notifyIDSessionExpired,
		)
		return
	}

	if se.Metadata != nil && se.Metadata[authsession.MetaWarning] == "true" {
		if se.Metadata[authsession.MetaFinal] == "true" {
			t.openSessionExpiration()
			return
		}
		t.notifySessionWarning(
			t.loc.T("notify.sessionWarning.title"),
			t.buildSessionWarningBody(se.Metadata),
		)
		return
	}

	body := se.UserMessage
	if id := se.Metadata["id"]; id != "" {
		body += fmt.Sprintf(" ID: %s", id)
	}
	t.notify(eventTitle(se), body, notifyIDEvent+se.ID)
}

// eventTitle composes a notification title from a SystemEvent's severity and
// category — "Critical: DNS", "Warning: Authentication", etc. — matching the
// format the legacy Fyne event.Manager produced.
func eventTitle(e services.SystemEvent) string {
	prefix := titleCase(e.Severity)
	if prefix == "" {
		prefix = "Info"
	}
	category := titleCase(e.Category)
	if category == "" {
		category = "System"
	}
	return prefix + ": " + category
}

func titleCase(s string) string {
	if s == "" {
		return ""
	}
	return strings.ToUpper(s[:1]) + strings.ToLower(s[1:])
}

// shouldSkipSystemEvent reports whether a daemon SystemEvent must not
// surface as a tray notification. Three sources are filtered out:
//   - update-available announcements (trayUpdater emits its own richer
//     notification when EventUpdateState fires)
//   - install-progress signals (consumed by the install-progress window)
//   - the ::/0 partner of an exit-node default-route event (the 0.0.0.0/0
//     partner already drove the user-facing toast, so the v6 row is
//     suppressed to avoid a duplicate notification)
func shouldSkipSystemEvent(se services.SystemEvent) bool {
	// The daemon's MDM "policy_applied" event carries a hardcoded English
	// UserMessage. The tray shows its own localised toast on the paired
	// config_changed (source=mdm) event instead, so drop this one to avoid
	// a duplicate, non-localised notification.
	if se.Metadata[proto.MetadataTypeKey] == proto.MetadataTypePolicyApplied {
		return true
	}
	if _, isUpdate := se.Metadata["new_version_available"]; isUpdate {
		return true
	}
	if _, isProgress := se.Metadata["progress_window"]; isProgress {
		return true
	}
	if se.Category == "network" && se.Metadata["network"] == "::/0" {
		return true
	}
	return false
}
