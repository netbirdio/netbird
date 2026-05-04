//go:build !windows

package notifier

import "fyne.io/fyne/v2"

func newNotifier(app fyne.App) Notifier {
	return &fyneNotifier{app: app}
}
