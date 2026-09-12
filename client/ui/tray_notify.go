//go:build !android && !ios && !freebsd && !js

package main

import (
	"context"

	log "github.com/sirupsen/logrus"
	"github.com/wailsapp/wails/v3/pkg/services/notifications"

	"github.com/netbirdio/netbird/client/ui/services"
)

const notifyIDDaemonOutdated = "netbird-daemon-outdated"

// sendFn fits both NotificationService.SendNotification and SendNotificationWithActions.
type sendFn func(notifications.NotificationOptions) error

// safeSendNotification sends a best-effort OS notification, swallowing errors and panics.
//
// The panic guard is load-bearing on Linux: when Wails' notifier fails to
// connect the session bus at startup (headless, unreachable
// DBUS_SESSION_BUS_ADDRESS) it stays registered with a nil *dbus.Conn, so the
// next send nil-derefs inside godbus. Because sends run on a Wails
// event-dispatch goroutine that panic is fatal process-wide; recover() turns
// it into a logged no-op.
func safeSendNotification(send sendFn, what string, opts notifications.NotificationOptions) (err error) {
	if services.ShuttingDown() {
		return nil
	}
	defer func() {
		if r := recover(); r != nil {
			log.Errorf("notify %s: recovered from panic (notification bus unavailable): %v", what, r)
			err = nil
		}
	}()
	if err := send(opts); err != nil {
		log.Errorf("notify %s: %v", what, err)
		return err
	}
	return nil
}

// registerNotificationResponses installs the single Wails notification-response
// callback and fans it out per category; a second OnNotificationResponse call
// would silently replace the first, so every category must branch here.
func (t *Tray) registerNotificationResponses() {
	if t.svc.Notifier == nil {
		return
	}
	t.svc.Notifier.OnNotificationResponse(func(result notifications.NotificationResult) {
		if result.Error != nil {
			log.Debugf("notification response error: %v", result.Error)
			return
		}
		switch result.Response.CategoryID {
		case notifyCategorySessionWarning:
			t.handleSessionWarningResponse(result.Response)
		case notifyCategoryFileDropOffer:
			t.handleFileDropResponse(result.Response)
		}
	})
}

// notifyIfDaemonOutdated probes the daemon once and fires an OS toast when it
// is reachable but too old for this UI. A probe error means the daemon isn't
// reachable (not outdated), so it is left to the normal connection flow.
func notifyIfDaemonOutdated(compat *services.Compat, notifier *Notifier, loc *Localizer) {
	ready, err := compat.DaemonReady(context.Background())
	if err != nil {
		log.Debugf("daemon compatibility probe: %v", err)
		return
	}
	if ready {
		return
	}
	_ = safeSendNotification(notifier.SendNotification, "daemon-outdated", notifications.NotificationOptions{
		ID:    notifyIDDaemonOutdated,
		Title: loc.T("notify.daemonOutdated.title"),
		Body:  loc.T("notify.daemonOutdated.body"),
	})
}
