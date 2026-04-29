package notifier

import (
	"os"
	"path/filepath"
	"sync"

	"fyne.io/fyne/v2"
	toast "git.sr.ht/~jackmordaunt/go-toast/v2"
	"git.sr.ht/~jackmordaunt/go-toast/v2/wintoast"
	log "github.com/sirupsen/logrus"
)

const (
	// appID is the AppUserModelID shown in the Windows Action Center. It
	// must match the System.AppUserModel.ID property set on the Start Menu
	// shortcut by the MSI (see client/netbird.wxs); otherwise Windows
	// groups toasts under a separate, unbranded entry.
	appID = "NetBird"

	// appGUID identifies the COM activation callback class. Generated once
	// for NetBird; do not change without coordinating an installer bump,
	// since old registry entries pointing at the previous GUID would orphan.
	appGUID = "{0E1B4DE7-E148-432B-9814-544F941826EC}"
)

type comNotifier struct {
	fallback *fyneNotifier
	ready    bool
	iconPath string
}

var (
	initOnce sync.Once
	initErr  error
)

func newNotifier(app fyne.App) Notifier {
	n := &comNotifier{
		fallback: &fyneNotifier{app: app},
		iconPath: resolveIcon(),
	}
	initOnce.Do(func() {
		initErr = wintoast.SetAppData(wintoast.AppData{
			AppID:    appID,
			GUID:     appGUID,
			IconPath: n.iconPath,
		})
	})
	if initErr != nil {
		log.Warnf("toast: register app data failed, falling back to fyne notifications: %v", initErr)
		return n.fallback
	}
	n.ready = true
	return n
}

func (n *comNotifier) Send(title, body string) {
	if !n.ready {
		n.fallback.Send(title, body)
		return
	}
	notification := toast.Notification{
		AppID: appID,
		Title: title,
		Body:  body,
		Icon:  n.iconPath,
	}
	if err := notification.Push(); err != nil {
		log.Warnf("toast: push failed, using fyne fallback: %v", err)
		n.fallback.Send(title, body)
	}
}

// resolveIcon returns an absolute path to the toast icon, or an empty string
// when no icon can be located. Windows requires a PNG/JPG for the
// AppUserModelId IconUri registry value; .ico is silently ignored.
func resolveIcon() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	candidate := filepath.Join(filepath.Dir(exe), "netbird.png")
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}
	return ""
}
