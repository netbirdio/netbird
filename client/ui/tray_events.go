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

// onSystemEvent fires an OS notification for daemon SystemEvents that carry a
// user-facing message. Gated by the "Notifications" toggle; critical events bypass it.
func (t *Tray) onSystemEvent(ev *application.CustomEvent) {
	se, ok := ev.Data.(services.SystemEvent)
	if !ok {
		return
	}
	// config_changed carries no UserMessage, so handle it before the message gate below.
	if se.Category == "system" && se.Metadata[proto.MetadataTypeKey] == proto.MetadataTypeConfigChanged {
		log.Infof("config_changed event received (source=%s); refreshing tray restrictions", se.Metadata[proto.MetadataSourceKey])
		go t.refreshRestrictions()
		go t.loadConfig()
		// MDM gets a localised toast here; the daemon's English "policy_applied"
		// event is suppressed in shouldSkipSystemEvent. Other sources stay silent.
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
	// Session-warning and deadline-rejected events build their body locally from
	// metadata; every other event needs a UserMessage.
	isSessionWarning := se.Metadata[authsession.MetaWarning] == "true"
	isDeadlineRejected := se.Metadata[authsession.MetaDeadlineRejected] != ""
	if !isSessionWarning && !isDeadlineRejected && se.UserMessage == "" {
		return
	}
	if shouldSkipSystemEvent(se) {
		return
	}

	critical := strings.EqualFold(se.Severity, services.SeverityCritical)
	t.profileMu.Lock()
	enabled := t.notificationsEnabled
	t.profileMu.Unlock()
	if !enabled && !critical {
		return
	}

	// Session-warning events route via stable metadata flags rather than
	// category/severity so a daemon-side reword still lands here. Final warning
	// auto-opens the SessionExpiration dialog with no notification (the dialog is
	// the last-chance reminder; doubling up would be noise).
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

// eventTitle composes a notification title, e.g. "Critical: DNS", "Warning: Authentication".
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

// shouldSkipSystemEvent reports whether a daemon SystemEvent must not surface as
// a tray notification:
//   - update-available announcements (trayUpdater emits its own)
//   - install-progress signals (consumed by the install-progress window)
//   - the ::/0 partner of an exit-node default route (0.0.0.0/0 already toasted)
func shouldSkipSystemEvent(se services.SystemEvent) bool {
	// "policy_applied" carries a hardcoded English message; the localised toast
	// fires on the paired config_changed (source=mdm) event instead.
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
