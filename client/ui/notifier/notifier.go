// Package notifier sends desktop notifications. On Windows it uses the WinRT
// COM API directly via go-toast/v2 to avoid the PowerShell window flash that
// fyne's default implementation produces. On other platforms it delegates to
// fyne.
package notifier

import "fyne.io/fyne/v2"

// Notifier sends desktop notifications.
type Notifier interface {
	Send(title, body string)
}

// New returns a platform-specific Notifier. The fyne app is used as the
// fallback notifier on platforms where no native implementation is wired up,
// and on Windows when the COM path fails to initialize.
func New(app fyne.App) Notifier {
	return newNotifier(app)
}

type fyneNotifier struct {
	app fyne.App
}

func (f *fyneNotifier) Send(title, body string) {
	f.app.SendNotification(fyne.NewNotification(title, body))
}
