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
	// config_changed carries no user-facing message, so handle it before the gate below.
	if se.Category == "system" && se.Metadata[proto.MetadataTypeKey] == proto.MetadataTypeConfigChanged {
		log.Infof("config_changed event received (source=%s); refreshing tray restrictions", se.Metadata[proto.MetadataSourceKey])
		go t.refreshRestrictions()
		go t.loadConfig()
		return
	}
	if se.MessageKey == "" && se.UserMessage == "" {
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

	body := t.localizedEventMessage(se)

	// The final session warning auto-opens the SessionExpiration dialog instead of
	// toasting: the dialog is the last-chance reminder and doubling up would be
	// noise. This routes on metadata rather than the message key because it is a
	// behavioural distinction, not a wording one.
	if se.Metadata[authsession.MetaWarning] == "true" {
		if se.Metadata[authsession.MetaFinal] == "true" {
			deadline, _ := authsession.ParseExpiresAt(se.Metadata[authsession.MetaExpiresAt])
			t.openSessionExpiration(deadline)
			return
		}
		t.notifySessionWarning(t.eventTitle(se), body)
		return
	}

	if id := se.Metadata["id"]; id != "" {
		body += fmt.Sprintf(" ID: %s", id)
	}
	t.notify(t.eventTitle(se), body, notifyIDEvent+se.ID)
}

// localizedEventMessage resolves the daemon's message key against the active
// locale. A key this build does not ship — a daemon newer than the UI — falls
// back to the daemon's own English rendering rather than showing a bare key.
func (t *Tray) localizedEventMessage(se services.SystemEvent) string {
	if body, ok := t.loc.Lookup(se.MessageKey, se.MessageArgs); ok {
		return body
	}
	if se.MessageKey != "" {
		log.Debugf("no translation for event message key %q, using the daemon's text", se.MessageKey)
	}
	return se.UserMessage
}

// eventTitle resolves the event's own title key, falling back to a title
// composed from severity and category, e.g. "Critical: DNS" in English. An enum
// value this build does not know falls back to the Info and System labels.
func (t *Tray) eventTitle(se services.SystemEvent) string {
	if title, ok := t.loc.Lookup(se.TitleKey, nil); ok {
		return title
	}
	severity, ok := t.loc.Lookup("event.severity."+strings.ToLower(se.Severity), nil)
	if !ok {
		severity = t.loc.T("event.severity.info")
	}
	category, ok := t.loc.Lookup("event.category."+strings.ToLower(se.Category), nil)
	if !ok {
		category = t.loc.T("event.category.system")
	}
	return t.loc.T("event.title", "severity", severity, "category", category)
}

// shouldSkipSystemEvent reports whether a daemon SystemEvent must not surface as
// a tray notification:
//   - update-available announcements (trayUpdater emits its own)
//   - install-progress signals (consumed by the install-progress window)
//   - the ::/0 partner of an exit-node default route (0.0.0.0/0 already toasted)
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
