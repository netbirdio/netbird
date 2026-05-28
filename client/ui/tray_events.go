//go:build !android && !ios && !freebsd && !js

package main

import (
	"fmt"
	"strings"

	"github.com/wailsapp/wails/v3/pkg/application"

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
	// Session-warning events carry no UserMessage — the tray builds the
	// localised notification body locally from metadata. Every other
	// event needs a non-empty UserMessage to show anything meaningful.
	isSessionWarning := se.Metadata[authsession.MetaWarning] == "true"
	if !isSessionWarning && se.UserMessage == "" {
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
	//     SessionAboutToExpire dialog. No OS notification here; the
	//     dialog is the last-chance reminder, doubling up would be noise.
	if se.Metadata != nil && se.Metadata[authsession.MetaWarning] == "true" {
		if se.Metadata[authsession.MetaFinal] == "true" {
			t.openSessionAboutToExpire()
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
