//go:build !android && !ios && !freebsd && !js

package main

import (
	"context"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/wailsapp/wails/v3/pkg/services/notifications"

	nbstatus "github.com/netbirdio/netbird/client/status"
	"github.com/netbirdio/netbird/client/ui/authsession"
	"github.com/netbirdio/netbird/client/ui/services"
)

const (
	notifyIDSessionExpired = "netbird-session-expired"
	notifyIDSessionWarning = "netbird-session-warning"

	// notifyCategorySessionWarning groups the "Extend now" / "Dismiss"
	// actions on the T-10min OS notification. Registered once at tray
	// construction with the Wails notifications service; subsequent
	// SendNotificationWithActions calls reference it by ID.
	notifyCategorySessionWarning = "netbird-session-warning"
	notifyActionExtendNow        = "extend-now"
	notifyActionDismiss          = "dismiss"

	// finalWarningCountdownSeconds is the countdown shown in the auto-opened
	// SessionExpiration dialog. Mirrors sessionwatch.FinalWarningLead
	// (2 minutes); the values stay in sync by hand because the lead is fixed
	// for the initial rollout.
	finalWarningCountdownSeconds = 120
)

// handleSessionExpired surfaces the SSO re-authentication path when the
// daemon reports StatusSessionExpired. Posts a single OS notification
// (the applyStatus guard ensures it fires only on the transition, not
// on every status snapshot) and brings the main window forward so the
// frontend's /login route can drive the renewed SSO flow. Mirrors the
// Fyne client's onSessionExpire, which used a runSelfCommand to spawn
// the login-url helper; here the window is already in-process.
func (t *Tray) handleSessionExpired() {
	t.notify(t.loc.T("notify.sessionExpired.title"), t.loc.T("notify.sessionExpired.body"), notifyIDSessionExpired)
	if t.window != nil {
		t.window.SetURL("/#/login")
		t.window.Show()
		t.window.Focus()
	}
}

// applySessionExpiry refreshes the "Session: 47m" tray row from the latest
// SSO deadline carried on the Status snapshot. Hidden when no deadline is
// tracked or the tunnel is down; otherwise renders the remaining time via
// formatSessionRemaining.
func (t *Tray) applySessionExpiry(deadline *time.Time, connected bool) {
	var d time.Time
	if connected && deadline != nil {
		d = *deadline
	}

	t.sessionMu.Lock()
	changed := !t.sessionExpiresAt.Equal(d)
	t.sessionExpiresAt = d
	t.sessionMu.Unlock()

	if changed {
		switch {
		case deadline == nil:
			log.Infof("tray applySessionExpiry: deadline=<nil> connected=%v → row hidden", connected)
		case deadline.IsZero():
			log.Infof("tray applySessionExpiry: deadline=<zero> connected=%v → row hidden", connected)
		default:
			log.Infof("tray applySessionExpiry: deadline=%s (in %s) connected=%v",
				deadline.Format(time.RFC3339), time.Until(*deadline), connected)
		}
	}

	if t.sessionExpiresItem == nil {
		return
	}
	if d.IsZero() {
		t.sessionExpiresItem.SetHidden(true)
		return
	}
	remaining := t.formatSessionRemaining(time.Until(d))
	t.sessionExpiresItem.SetLabel(t.loc.T("tray.session.expiresIn", "remaining", remaining))
	t.sessionExpiresItem.SetHidden(false)
}

// runSessionExpiryTicker keeps the "Expires in …" countdown row fresh by
// recomputing its label every 30 seconds for the app's lifetime. Started
// once on ApplicationStarted; the goroutine lives until the process exits.
func (t *Tray) runSessionExpiryTicker() {
	tk := time.NewTicker(30 * time.Second)
	for range tk.C {
		t.refreshSessionExpiresLabel()
	}
}

// refreshSessionExpiresLabel recomputes the "Session expires in …" tray
// row label from the cached SSO deadline.
func (t *Tray) refreshSessionExpiresLabel() {
	if t.sessionExpiresItem == nil {
		return
	}
	t.sessionMu.Lock()
	deadline := t.sessionExpiresAt
	t.sessionMu.Unlock()
	if deadline.IsZero() {
		return
	}
	remaining := t.formatSessionRemaining(time.Until(deadline))
	t.sessionExpiresItem.SetLabel(t.loc.T("tray.session.expiresIn", "remaining", remaining))
}

// formatSessionRemaining renders the time-to-deadline as a localised
// long-form string ("47 minutes", "2 hours", "1 day"). Picks the
// largest unit that fits non-zero and keeps singular/plural distinct
// — the unit name keys (`tray.session.unit.minute(s)|hour(s)|day(s)`)
// are split per language so translators can spell each form properly.
// Sub-minute deltas read as "less than a minute" so a countdown that
// has rolled past zero between Status pushes still produces something
// sensible.
func (t *Tray) formatSessionRemaining(d time.Duration) string {
	switch {
	case d < time.Minute:
		return t.loc.T("tray.session.unit.lessThanMinute")
	case d < time.Hour:
		m := int(d / time.Minute)
		if m == 1 {
			return t.loc.T("tray.session.unit.minute")
		}
		return t.loc.T("tray.session.unit.minutes", "count", strconv.Itoa(m))
	case d < 24*time.Hour:
		h := int((d + 30*time.Minute) / time.Hour)
		if h == 1 {
			return t.loc.T("tray.session.unit.hour")
		}
		return t.loc.T("tray.session.unit.hours", "count", strconv.Itoa(h))
	default:
		days := int((d + 12*time.Hour) / (24 * time.Hour))
		if days == 1 {
			return t.loc.T("tray.session.unit.day")
		}
		return t.loc.T("tray.session.unit.days", "count", strconv.Itoa(days))
	}
}

// registerSessionWarningCategory wires the OS notification category for the
// T-10min SSO expiry warning. The category carries two actions ("Extend now"
// and "Dismiss") and the global response handler so a click resolves back
// into runExtendSession. Idempotent — called once from NewTray; errors are
// logged and swallowed because the worst case is a plain text notification
// without buttons.
func (t *Tray) registerSessionWarningCategory() {
	if t.svc.Notifier == nil {
		return
	}
	if err := t.svc.Notifier.RegisterNotificationCategory(notifications.NotificationCategory{
		ID: notifyCategorySessionWarning,
		Actions: []notifications.NotificationAction{
			{ID: notifyActionExtendNow, Title: t.loc.T("notify.sessionWarning.extend")},
			{ID: notifyActionDismiss, Title: t.loc.T("notify.sessionWarning.dismiss")},
		},
	}); err != nil {
		log.Debugf("register session-warning notification category: %v", err)
	}
	t.svc.Notifier.OnNotificationResponse(func(result notifications.NotificationResult) {
		if result.Error != nil {
			log.Debugf("notification response error: %v", result.Error)
			return
		}
		if result.Response.CategoryID != notifyCategorySessionWarning {
			return
		}
		switch result.Response.ActionIdentifier {
		case notifyActionExtendNow, notifications.DefaultActionIdentifier:
			// DefaultActionIdentifier covers the body-click on platforms
			// that don't expose buttons separately (e.g. some minimal
			// Linux notification daemons fall back to a single click
			// area). Treat it as Extend so the user always has a path.
			go t.runExtendSession()
		case notifyActionDismiss:
			// Explicit user opt-out. Tell the daemon so the
			// T-FinalWarningLead fallback dialog stays closed for this
			// deadline; the regular watcher remains armed for the next
			// deadline value (e.g. after a successful extend elsewhere).
			go t.dismissSessionWarning()
		}
	})
}

// buildSessionWarningBody composes the localised body for the T-10min
// notification from the daemon's metadata. The daemon does not have a
// locale, so it ships a stable RFC3339 deadline ("session_expires_at")
// and integer lead time ("lead_minutes") in metadata; the tray turns
// them into a user-language sentence via the active i18n bundle.
//
// Falls back to a constant string when the metadata is missing or the
// timestamp fails to parse — the user still sees the warning, just
// without the remaining-time count.
func (t *Tray) buildSessionWarningBody(meta map[string]string) string {
	if meta == nil {
		return t.loc.T("notify.sessionWarning.bodyGeneric")
	}
	raw := meta[authsession.MetaExpiresAt]
	if raw == "" {
		return t.loc.T("notify.sessionWarning.bodyGeneric")
	}
	deadline, err := authsession.ParseExpiresAt(raw)
	if err != nil {
		return t.loc.T("notify.sessionWarning.bodyGeneric")
	}
	remaining := nbstatus.FormatRemainingDuration(time.Until(deadline))
	return t.loc.T("notify.sessionWarning.body", "remaining", remaining)
}

// notifySessionWarning sends the interactive T-10min OS notification. Falls
// back to the plain `notify` helper if the Wails service doesn't expose the
// with-actions variant (older platform impls, or a bare Notifier in tests).
func (t *Tray) notifySessionWarning(title, body string) {
	if t.svc.Notifier == nil {
		return
	}
	err := t.svc.Notifier.SendNotificationWithActions(notifications.NotificationOptions{
		ID:         notifyIDSessionWarning,
		Title:      title,
		Body:       body,
		CategoryID: notifyCategorySessionWarning,
	})
	if err != nil {
		log.Debugf("notify session-warning with actions: %v", err)
		// Fall back to a plain notification so the user at least gets
		// the warning text, even without buttons.
		t.notify(title, body, notifyIDSessionWarning)
	}
}

// runExtendSession drives the daemon's RequestExtendAuthSession +
// WaitExtendAuthSession pair when the user clicks "Extend now" on the
// session-warning notification. Mirrors `doExtendSession` in
// client/cmd/login.go but talks to the in-process Wails Session service
// instead of opening a daemon gRPC channel from a CLI process. The
// browser is opened via Connection.OpenURL (which honours $BROWSER on
// Unix). Errors surface as plain notifyError calls — there is no foreground
// UI flow here because the warning may fire while the main window is
// closed.
func (t *Tray) runExtendSession() {
	if t.svc.Session == nil || t.svc.Connection == nil {
		log.Debugf("session-warning: extend requested but services not wired")
		return
	}
	ctx := context.Background()

	start, err := t.svc.Session.RequestExtend(ctx, services.ExtendStartParams{})
	if err != nil {
		log.Warnf("session-warning: RequestExtend failed: %v", err)
		t.notifyError(t.loc.T("notify.sessionWarning.failed"))
		return
	}

	uri := start.VerificationURIComplete
	if uri == "" {
		uri = start.VerificationURI
	}
	if uri != "" {
		if err := t.svc.Connection.OpenURL(uri); err != nil {
			log.Debugf("session-warning: opening verification URL: %v", err)
		}
	}

	result, err := t.svc.Session.WaitExtend(ctx, services.ExtendWaitParams{
		DeviceCode: start.DeviceCode,
		UserCode:   start.UserCode,
	})
	if err != nil {
		log.Warnf("session-warning: WaitExtend failed: %v", err)
		t.notifyError(t.loc.T("notify.sessionWarning.failed"))
		return
	}
	if result.Preempted {
		// Another UI surface (e.g. the about-to-expire dialog) started a
		// flow for the same deadline and took over. Stay silent so the
		// user only sees the outcome of the surviving flow.
		log.Debugf("session-warning: WaitExtend preempted by a newer flow")
		return
	}
	t.notify(t.loc.T("notify.sessionWarning.successTitle"), t.loc.T("notify.sessionWarning.successBody"), notifyIDSessionWarning)
}

// dismissSessionWarning tells the daemon to silence the T-FinalWarningLead
// fallback dialog for the current deadline. Best-effort: a failure only
// means the dialog will still appear, so we log and move on.
func (t *Tray) dismissSessionWarning() {
	if t.svc.Session == nil {
		return
	}
	if err := t.svc.Session.DismissWarning(context.Background()); err != nil {
		log.Debugf("session-warning: DismissWarning failed: %v", err)
	}
}

// openSessionExpiration fires the auto-opened fallback dialog at
// T-FinalWarningLead when the user did not dismiss the earlier T-10
// notification. Idempotent on the WindowManager side (a second call
// while the window is already open is a no-op).
func (t *Tray) openSessionExpiration() {
	if t.svc.WindowManager == nil {
		return
	}
	t.svc.WindowManager.OpenSessionExpiration(finalWarningCountdownSeconds)
}

// openSessionExtendFlow opens the SessionExpiration window seeded with
// the actual remaining time on the cached SSO deadline. Triggered by a
// click on the "Expires in …" tray row so the user can extend the session
// proactively, instead of waiting for the daemon's T-FinalWarningLead
// auto-prompt. Silently no-ops when the deadline is unknown or already
// elapsed — the menu row is hidden in those states anyway.
func (t *Tray) openSessionExtendFlow() {
	if t.svc.WindowManager == nil {
		return
	}
	t.sessionMu.Lock()
	deadline := t.sessionExpiresAt
	t.sessionMu.Unlock()
	if deadline.IsZero() {
		return
	}
	seconds := int(time.Until(deadline).Seconds())
	if seconds <= 0 {
		return
	}
	t.svc.WindowManager.OpenSessionExpiration(seconds)
}
