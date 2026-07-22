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

	notifyCategorySessionWarning = "netbird-session-warning"
	notifyActionExtendNow        = "extend-now"
	notifyActionDismiss          = "dismiss"

	// finalWarningCountdownSeconds must stay in sync by hand with sessionwatch.FinalWarningLead.
	finalWarningCountdownSeconds = 120
)

// handleSessionExpired notifies and brings the window forward so the frontend's /login route drives renewal.
func (t *Tray) handleSessionExpired() {
	t.notify(t.loc.T("notify.sessionExpired.title"), t.loc.T("notify.sessionExpired.body"), notifyIDSessionExpired)
	if t.window != nil {
		t.window.SetURL("/#/login")
		t.window.Show()
		t.window.Focus()
	}
}

// applySessionExpiry refreshes the cached SSO deadline and reports whether it changed.
// Cache-only; the caller relayouts when this returns true.
func (t *Tray) applySessionExpiry(deadline *time.Time, connected bool) bool {
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
	return changed
}

// runSessionExpiryTicker recomputes the "Expires in …" row label until process exit.
// The interval scales with the remaining time: coarse when the deadline is far off,
// down to 10s in the final two minutes so the label doesn't lag the ceiling-rounded
// countdown near expiry. The cached deadline is re-read every iteration, so an extend
// or reconnect that moves it is picked up on the next tick.
func (t *Tray) runSessionExpiryTicker() {
	tm := time.NewTimer(sessionRefreshInterval(t.sessionRemaining()))
	defer tm.Stop()
	for range tm.C {
		t.refreshSessionExpiresLabel()
		tm.Reset(sessionRefreshInterval(t.sessionRemaining()))
	}
}

// sessionRemaining returns the time left on the cached SSO deadline, or 0 when unknown.
func (t *Tray) sessionRemaining() time.Duration {
	t.sessionMu.Lock()
	deadline := t.sessionExpiresAt
	t.sessionMu.Unlock()
	if deadline.IsZero() {
		return 0
	}
	return time.Until(deadline)
}

// sessionRefreshInterval picks how long to wait before the next label recompute.
func sessionRefreshInterval(remaining time.Duration) time.Duration {
	switch {
	case remaining <= 0:
		return 30 * time.Second
	case remaining <= 2*time.Minute:
		return 10 * time.Second
	case remaining <= time.Hour:
		return 30 * time.Second
	default:
		return time.Minute
	}
}

// refreshSessionExpiresLabel updates only the countdown label, no relayout, to avoid disturbing an open menu.
// The item is snapshotted under menuMu since buildMenu reassigns it on every relayout.
func (t *Tray) refreshSessionExpiresLabel() {
	t.menuMu.Lock()
	item := t.sessionExpiresItem
	t.menuMu.Unlock()
	if item == nil {
		return
	}
	t.sessionMu.Lock()
	deadline := t.sessionExpiresAt
	t.sessionMu.Unlock()
	if deadline.IsZero() {
		return
	}
	item.SetLabel(t.sessionRowLabel(deadline))
}

func (t *Tray) sessionRowLabel(deadline time.Time) string {
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return t.loc.T("tray.status.sessionExpired")
	}
	return t.loc.T("tray.session.expiresIn", "remaining", t.formatSessionRemaining(remaining))
}

// formatSessionRemaining renders d as a localised long-form string picking the largest non-zero unit.
// Each unit is rounded up so the label never claims less time than actually remains, matching the
// upper-bound sense of the sub-minute "less than a minute" fragment.
// Singular/plural keys are split per language for proper translation.
func (t *Tray) formatSessionRemaining(d time.Duration) string {
	switch {
	case d < time.Minute:
		return t.loc.T("tray.session.unit.lessThanMinute")
	case d <= 59*time.Minute:
		m := ceilDiv(d, time.Minute)
		if m == 1 {
			return t.loc.T("tray.session.unit.minute")
		}
		return t.loc.T("tray.session.unit.minutes", "count", strconv.Itoa(m))
	case d <= 23*time.Hour:
		h := ceilDiv(d, time.Hour)
		if h == 1 {
			return t.loc.T("tray.session.unit.hour")
		}
		return t.loc.T("tray.session.unit.hours", "count", strconv.Itoa(h))
	default:
		days := ceilDiv(d, 24*time.Hour)
		if days == 1 {
			return t.loc.T("tray.session.unit.day")
		}
		return t.loc.T("tray.session.unit.days", "count", strconv.Itoa(days))
	}
}

// ceilDiv divides d by unit rounding up, assuming d > 0.
func ceilDiv(d, unit time.Duration) int {
	return int((d + unit - time.Nanosecond) / unit)
}

// registerSessionWarningCategory wires the OS notification category and response handler for the expiry warning.
// Errors are swallowed since the worst case is a plain notification without buttons.
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
			// DefaultActionIdentifier is the body-click on platforms with no separate buttons; treat as Extend.
			go t.runExtendSession()
		case notifyActionDismiss:
			go t.dismissSessionWarning()
		}
	})
}

// buildSessionWarningBody composes the localised notification body from the daemon's metadata.
// The daemon has no locale, so it ships an RFC3339 deadline the tray turns into a user-language sentence.
// Falls back to a generic string when metadata is missing or unparsable.
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

// notifySessionWarning sends the interactive expiry notification, falling back to plain notify when the
// with-actions variant is unavailable (older platform impls, or a bare Notifier in tests).
func (t *Tray) notifySessionWarning(title, body string) {
	if t.svc.Notifier == nil {
		return
	}
	err := safeSendNotification(t.svc.Notifier.SendNotificationWithActions, "session-warning with actions", notifications.NotificationOptions{
		ID:         notifyIDSessionWarning,
		Title:      title,
		Body:       body,
		CategoryID: notifyCategorySessionWarning,
	})
	if err != nil {
		// A recovered panic returns nil err, so a dead bus correctly skips this fallback (it would panic too).
		t.notify(title, body, notifyIDSessionWarning)
	}
}

// runExtendSession drives the daemon's RequestExtend + WaitExtend pair, opening the browser via Connection.OpenURL.
// Errors surface as notifyError rather than foreground UI, since the warning may fire while the window is closed.
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
		// Another UI surface owns the flow; stay silent so the user only sees the surviving flow's outcome.
		log.Debugf("session-warning: WaitExtend preempted by a newer flow")
		return
	}
	t.notify(t.loc.T("notify.sessionWarning.successTitle"), t.loc.T("notify.sessionWarning.successBody"), notifyIDSessionWarning)
}

// dismissSessionWarning tells the daemon to silence the fallback dialog for the current deadline.
// Best-effort: a failure only means the dialog will still appear.
func (t *Tray) dismissSessionWarning() {
	if t.svc.Session == nil {
		return
	}
	if err := t.svc.Session.DismissWarning(context.Background()); err != nil {
		log.Debugf("session-warning: DismissWarning failed: %v", err)
	}
}

// openSessionExpiration fires the fallback dialog when the earlier warning notification wasn't dismissed.
// Idempotent on the WindowManager side.
func (t *Tray) openSessionExpiration() {
	if t.svc.WindowManager == nil {
		return
	}
	t.svc.WindowManager.OpenSessionExpiration(finalWarningCountdownSeconds)
}

// openSessionExtendFlow opens the SessionExpiration window seeded with the cached deadline's remaining time,
// for the "Expires in …" tray row. Once the deadline has elapsed the row reads "Session expired" and the
// click routes to the login flow instead. No-op when the deadline is unknown.
func (t *Tray) openSessionExtendFlow() {
	t.sessionMu.Lock()
	deadline := t.sessionExpiresAt
	t.sessionMu.Unlock()
	if deadline.IsZero() {
		return
	}
	seconds := int(time.Until(deadline).Seconds())
	if seconds <= 0 {
		if t.window != nil {
			t.window.SetURL("/#/login")
			t.window.Show()
			t.window.Focus()
		}
		return
	}
	if t.svc.WindowManager == nil {
		return
	}
	t.svc.WindowManager.OpenSessionExpiration(seconds)
}
