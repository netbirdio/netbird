//go:build !android && !ios && !freebsd && !js

package main

import (
	log "github.com/sirupsen/logrus"
	"github.com/wailsapp/wails/v3/pkg/services/notifications"
)

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
