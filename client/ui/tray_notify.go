//go:build !android && !ios && !freebsd && !js

package main

import (
	log "github.com/sirupsen/logrus"
	"github.com/wailsapp/wails/v3/pkg/services/notifications"
)

// sendFn is either NotificationService.SendNotification or
// SendNotificationWithActions — both share the same signature.
type sendFn func(notifications.NotificationOptions) error

// safeSendNotification dispatches an OS notification, swallowing both errors
// and panics. OS toasts are best-effort: a missing or broken session bus must
// never crash the app.
//
// The panic guard is load-bearing on Linux. Wails' notifier connects to the
// session bus in its ServiceStartup; when that connect fails (headless box,
// no/unreachable DBUS_SESSION_BUS_ADDRESS, a UI launched outside a desktop
// session), Wails logs the error but leaves the service registered with a nil
// *dbus.Conn. The next SendNotification then nil-derefs deep inside
// godbus (Conn.getSerial) and, because the send runs on a Wails event-dispatch
// goroutine, the panic is fatal to the whole process rather than to one event
// listener. recover() turns that into a logged no-op. See
// notifications_linux.go in wails v3.
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
